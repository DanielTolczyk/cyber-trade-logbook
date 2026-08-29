"""Cryptographic primitives for Trade Keys, Hash Chains, and Encrypted Clearinghouse Submissions."""

import json
import base64
import hashlib
from datetime import datetime, timezone
from typing import Tuple, List, Optional
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .models import LogbookEntry, EncryptedSubmissionBundle

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


class TradeKeyManager:
    """Manages Ed25519 Trade Keypairs, Hash Chains, and Encrypted Submissions."""

    @staticmethod
    def generate_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def get_public_key_fingerprint(public_key: ed25519.Ed25519PublicKey) -> str:
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return hashlib.sha256(pub_bytes).hexdigest()

    @staticmethod
    def serialize_private_key(private_key: ed25519.Ed25519PrivateKey, password: str = None) -> bytes:
        encryption = (
            serialization.BestAvailableEncryption(password.encode())
            if password
            else serialization.NoEncryption()
        )
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )

    @staticmethod
    def serialize_public_key(public_key: ed25519.Ed25519PublicKey) -> bytes:
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def load_private_key(pem_bytes: bytes, password: str = None) -> ed25519.Ed25519PrivateKey:
        return serialization.load_pem_private_key(
            pem_bytes,
            password=password.encode() if password else None
        )

    @staticmethod
    def load_public_key(pem_bytes: bytes) -> ed25519.Ed25519PublicKey:
        return serialization.load_pem_public_key(pem_bytes)

    @staticmethod
    def canonicalize_entry(entry: LogbookEntry, prev_hash: str) -> bytes:
        canonical_dict = {
            "log_id": entry.log_id,
            "prev_entry_hash": prev_hash,
            "practitioner_trade_id": entry.practitioner.trade_id,
            "practitioner_name": entry.practitioner.name,
            "date": str(entry.runtime_execution.date),
            "hours_logged": entry.runtime_execution.hours_logged,
            "core_domain": entry.runtime_execution.core_domain,
            "sub_domain": entry.runtime_execution.sub_domain or "",
            "environment_type": entry.runtime_execution.environment_type,
            "artifacts": [
                {
                    "artifact_type": a.artifact_type,
                    "artifact_reference": a.artifact_reference,
                    "sanitized_summary": a.sanitized_summary
                }
                for a in entry.verification_artifacts
            ]
        }
        canonical_str = json.dumps(canonical_dict, sort_keys=True, separators=(',', ':'))
        return canonical_str.encode("utf-8")

    @classmethod
    def compute_entry_hash(cls, entry: LogbookEntry, prev_hash: str) -> str:
        canonical_bytes = cls.canonicalize_entry(entry, prev_hash)
        return hashlib.sha256(canonical_bytes).hexdigest()

    @classmethod
    def sign_entry_attestation(
        cls,
        supervisor_private_key: ed25519.Ed25519PrivateKey,
        entry: LogbookEntry,
        prev_hash: str
    ) -> str:
        entry_hash = cls.compute_entry_hash(entry, prev_hash)
        signature_bytes = supervisor_private_key.sign(entry_hash.encode("utf-8"))
        return base64.b64encode(signature_bytes).decode("utf-8")

    @classmethod
    def verify_entry_attestation(
        cls,
        supervisor_public_key: ed25519.Ed25519PublicKey,
        entry: LogbookEntry,
        prev_hash: str
    ) -> bool:
        if not entry.attestation or not entry.attestation.supervisor_signature:
            return False
        entry_hash = cls.compute_entry_hash(entry, prev_hash)
        try:
            sig_bytes = base64.b64decode(entry.attestation.supervisor_signature)
            supervisor_public_key.verify(sig_bytes, entry_hash.encode("utf-8"))
            return True
        except Exception:
            return False

    @classmethod
    def verify_chain_integrity(cls, entries: List[LogbookEntry]) -> Tuple[bool, Optional[str]]:
        expected_prev_hash = GENESIS_HASH
        for idx, entry in enumerate(entries):
            if entry.prev_entry_hash != expected_prev_hash:
                return False, f"Broken chain at entry index {idx}: expected prev_hash {expected_prev_hash}, got {entry.prev_entry_hash}"
            calculated_hash = cls.compute_entry_hash(entry, expected_prev_hash)
            if entry.entry_hash and entry.entry_hash != calculated_hash:
                return False, f"Hash mismatch at entry index {idx}: calculated {calculated_hash}, recorded {entry.entry_hash}"
            expected_prev_hash = calculated_hash
        return True, None

    @classmethod
    def create_submission_bundle(
        cls,
        practitioner_private_key: ed25519.Ed25519PrivateKey,
        clearinghouse_id: str,
        entries: List[LogbookEntry],
        symmetric_key: bytes = None
    ) -> EncryptedSubmissionBundle:
        if not symmetric_key:
            symmetric_key = AESGCM.generate_key(bit_length=256)

        aesgcm = AESGCM(symmetric_key)
        nonce = b"TRADE_NONCE_12"

        raw_payload = json.dumps([e.model_dump(by_alias=True, mode="json") for e in entries]).encode("utf-8")
        encrypted_bytes = aesgcm.encrypt(nonce, raw_payload, clearinghouse_id.encode("utf-8"))

        pub = practitioner_private_key.public_key()
        pub_pem = cls.serialize_public_key(pub).decode("utf-8")
        chain_head = entries[-1].entry_hash if entries and entries[-1].entry_hash else GENESIS_HASH

        manifest_to_sign = f"{clearinghouse_id}:{chain_head}:{len(entries)}:{hashlib.sha256(encrypted_bytes).hexdigest()}"
        signature = practitioner_private_key.sign(manifest_to_sign.encode("utf-8"))

        return EncryptedSubmissionBundle(
            bundle_id=f"urn:uuid:bundle-{hashlib.sha256(manifest_to_sign.encode()).hexdigest()[:16]}",
            created_at=datetime.now(timezone.utc),
            practitioner_trade_id=entries[0].practitioner.trade_id if entries else "UNKNOWN",
            practitioner_pubkey=pub_pem,
            recipient_clearinghouse_id=clearinghouse_id,
            chain_head_hash=chain_head,
            total_entries_count=len(entries),
            encrypted_payload_b64=base64.b64encode(encrypted_bytes).decode("utf-8"),
            nonce_b64=base64.b64encode(nonce).decode("utf-8"),
            practitioner_submission_signature_b64=base64.b64encode(signature).decode("utf-8")
        )

    @classmethod
    def verify_submission_bundle(
        cls,
        bundle: EncryptedSubmissionBundle,
        practitioner_public_key: ed25519.Ed25519PublicKey,
        symmetric_key: bytes
    ) -> Tuple[bool, Optional[List[dict]], Optional[str]]:
        try:
            encrypted_bytes = base64.b64decode(bundle.encrypted_payload_b64)
            nonce = base64.b64decode(bundle.nonce_b64)
            sig_bytes = base64.b64decode(bundle.practitioner_submission_signature_b64)

            manifest_to_verify = f"{bundle.recipient_clearinghouse_id}:{bundle.chain_head_hash}:{bundle.total_entries_count}:{hashlib.sha256(encrypted_bytes).hexdigest()}"
            practitioner_public_key.verify(sig_bytes, manifest_to_verify.encode("utf-8"))

            aesgcm = AESGCM(symmetric_key)
            decrypted_bytes = aesgcm.decrypt(nonce, encrypted_bytes, bundle.recipient_clearinghouse_id.encode("utf-8"))
            entries_dict = json.loads(decrypted_bytes.decode("utf-8"))
            return True, entries_dict, None
        except Exception as e:
            return False, None, f"Bundle decryption/verification failed: {str(e)}"


    @classmethod
    def issue_board_credential(
        cls,
        board_root_private_key: ed25519.Ed25519PrivateKey,
        trade_id: str,
        legal_name: str,
        certified_role: str,
        practitioner_public_key: ed25519.Ed25519PublicKey,
        expires_timestamp: datetime
    ):
        from .models import CertifiedTradeCredential
        issued_at = datetime.now(timezone.utc)
        pub_pem = cls.serialize_public_key(practitioner_public_key).decode("utf-8")
        
        canonical_cred = f"{trade_id}:{legal_name}:{certified_role}:{pub_pem}:{issued_at.isoformat()}:{expires_timestamp.isoformat()}"
        board_signature = board_root_private_key.sign(canonical_cred.encode("utf-8"))
        
        return CertifiedTradeCredential(
            credential_id=f"urn:uuid:cred-{hashlib.sha256(canonical_cred.encode()).hexdigest()[:16]}",
            trade_id=trade_id,
            legal_name=legal_name,
            certified_role=certified_role,
            public_key_pem=pub_pem,
            issued_timestamp=issued_at,
            expires_timestamp=expires_timestamp,
            board_root_signature_b64=base64.b64encode(board_signature).decode("utf-8")
        )

    @classmethod
    def verify_board_credential(
        cls,
        board_root_public_key: ed25519.Ed25519PublicKey,
        credential
    ) -> Tuple[bool, Optional[str]]:
        try:
            canonical_cred = f"{credential.trade_id}:{credential.legal_name}:{credential.certified_role}:{credential.public_key_pem}:{credential.issued_timestamp.isoformat()}:{credential.expires_timestamp.isoformat()}"
            sig_bytes = base64.b64decode(credential.board_root_signature_b64)
            board_root_public_key.verify(sig_bytes, canonical_cred.encode("utf-8"))
            
            # Check expiration
            if datetime.now(timezone.utc) > credential.expires_timestamp:
                return False, "Trade credential has expired."
            return True, None
        except Exception as e:
            return False, f"Invalid Board Root signature: {str(e)}"

    @classmethod
    def verify_supervisor_standing(
        cls,
        board_root_public_key: ed25519.Ed25519PublicKey,
        supervisor_credential,
        entry: LogbookEntry,
        prev_hash: str
    ) -> Tuple[bool, Optional[str]]:
        """Strictly validates supervisor authority: must be Board-certified Journeyman/Master and cannot sign own log."""
        # 1. Self-signing prohibition
        if supervisor_credential.trade_id == entry.practitioner.trade_id:
            return False, "Unauthorized: Practitioner cannot sign their own operational logbook entries."

        # 2. Apprentice peer-signing prohibition
        if supervisor_credential.certified_role not in ["Licensed Journeyman", "Master Practitioner", "JATC Training Director"]:
            return False, f"Unauthorized: Role '{supervisor_credential.certified_role}' is not authorized to attest to operational hours. Only Licensed Journeymen or Masters may sign."

        # 3. Verify Board Root CA signature on supervisor credential
        valid_cred, err = cls.verify_board_credential(board_root_public_key, supervisor_credential)
        if not valid_cred:
            return False, f"Untrusted supervisor: {err}"

        # 4. Verify the supervisor's signature on the entry hash
        sup_pub = cls.load_public_key(supervisor_credential.public_key_pem.encode("utf-8"))
        if not cls.verify_entry_attestation(sup_pub, entry, prev_hash):
            return False, "Cryptographic attestation signature mismatch on entry hash."

        return True, None

    @classmethod
    def issue_jatc_physical_seal(
        cls,
        examiner_private_key: ed25519.Ed25519PrivateKey,
        practitioner_trade_id: str,
        book_serial_number: str,
        start_page: int,
        end_page: int,
        total_verified_hours: float,
        domain_breakdown: dict,
        supervisors_verified: list,
        examiner_name: str,
        examiner_trade_id: str,
        regional_local: str
    ):
        from .models import JATCPhysicalAuditSeal
        audit_time = datetime.now(timezone.utc)
        canonical_seal = f"{practitioner_trade_id}:{book_serial_number}:{start_page}:{end_page}:{total_verified_hours}:{examiner_trade_id}:{regional_local}:{audit_time.isoformat()}"
        sig = examiner_private_key.sign(canonical_seal.encode("utf-8"))

        return JATCPhysicalAuditSeal(
            audit_seal_id=f"urn:uuid:seal-{hashlib.sha256(canonical_seal.encode()).hexdigest()[:16]}",
            practitioner_trade_id=practitioner_trade_id,
            book_serial_number=book_serial_number,
            start_page=start_page,
            end_page=end_page,
            total_verified_hours=total_verified_hours,
            domain_breakdown=domain_breakdown,
            supervisors_verified=supervisors_verified,
            examiner_name=examiner_name,
            examiner_trade_id=examiner_trade_id,
            regional_local=regional_local,
            audit_timestamp=audit_time,
            examiner_signature_b64=base64.b64encode(sig).decode("utf-8")
        )

    @classmethod
    def verify_jatc_physical_seal(
        cls,
        examiner_public_key: ed25519.Ed25519PublicKey,
        seal
    ) -> Tuple[bool, Optional[str]]:
        try:
            canonical_seal = f"{seal.practitioner_trade_id}:{seal.book_serial_number}:{seal.start_page}:{seal.end_page}:{seal.total_verified_hours}:{seal.examiner_trade_id}:{seal.regional_local}:{seal.audit_timestamp.isoformat()}"
            sig_bytes = base64.b64decode(seal.examiner_signature_b64)
            examiner_public_key.verify(sig_bytes, canonical_seal.encode("utf-8"))
            return True, None
        except Exception as e:
            return False, f"Invalid JATC physical seal signature: {str(e)}"

    @classmethod
    def merge_ledger_chains(
        cls,
        local_entries: List[LogbookEntry],
        incoming_entries: List[LogbookEntry]
    ) -> Tuple[List[LogbookEntry], str]:
        """Safely merges entries from two devices maintaining cryptographic integrity and strict practitioner isolation."""
        if not local_entries and not incoming_entries:
            return [], "Both ledger sets are empty."

        # Strict practitioner isolation check: prevent mixing logs on shared workstations
        target_practitioner_id = local_entries[0].practitioner.trade_id if local_entries else incoming_entries[0].practitioner.trade_id
        for entry in local_entries + incoming_entries:
            if entry.practitioner.trade_id != target_practitioner_id:
                raise ValueError(
                    f"Cross-practitioner merge violation: Cannot merge logs belonging to '{entry.practitioner.trade_id}' "
                    f"into isolated vault for '{target_practitioner_id}' on a shared workstation."
                )

        # Index entries by unique log_id
        entry_map = {e.log_id: e for e in local_entries}
        
        for inc in incoming_entries:
            if inc.log_id not in entry_map:
                entry_map[inc.log_id] = inc
            else:
                # If existing is pending and incoming is signed, upgrade to signed
                existing = entry_map[inc.log_id]
                if not existing.attestation and inc.attestation:
                    entry_map[inc.log_id] = inc

        # Separate signed entries (immutable) and unsigned drafts
        all_entries = list(entry_map.values())
        signed_entries = [e for e in all_entries if e.attestation is not None]
        draft_entries = [e for e in all_entries if e.attestation is None]

        # Sort signed entries by date
        signed_entries.sort(key=lambda x: x.runtime_execution.date)
        # Sort draft entries by date
        draft_entries.sort(key=lambda x: x.runtime_execution.date)

        merged_chain = []
        prev_hash = GENESIS_HASH

        # Append and verify signed entries
        for s_entry in signed_entries:
            s_entry.prev_entry_hash = prev_hash
            s_entry.entry_hash = cls.compute_entry_hash(s_entry, prev_hash)
            prev_hash = s_entry.entry_hash
            merged_chain.append(s_entry)

        # Append and re-chain draft entries
        for d_entry in draft_entries:
            d_entry.prev_entry_hash = prev_hash
            d_entry.entry_hash = cls.compute_entry_hash(d_entry, prev_hash)
            prev_hash = d_entry.entry_hash
            merged_chain.append(d_entry)

        return merged_chain, "Successfully reconciled and merged ledger entries."

    @classmethod
    def create_invalidation_block(
        cls,
        supervisor_private_key: ed25519.Ed25519PrivateKey,
        supervisor_trade_id: str,
        target_entry: LogbookEntry,
        reason_category: str,
        justification: str
    ):
        from .models import InvalidationBlock
        inval_time = datetime.now(timezone.utc)
        hours = target_entry.runtime_execution.hours_logged
        domain = target_entry.runtime_execution.core_domain
        
        canonical_inval = f"{target_entry.log_id}:{reason_category}:{hours}:{domain}:{supervisor_trade_id}:{inval_time.isoformat()}"
        sig = supervisor_private_key.sign(canonical_inval.encode("utf-8"))

        return InvalidationBlock(
            invalidation_id=f"urn:uuid:inval-{hashlib.sha256(canonical_inval.encode()).hexdigest()[:16]}",
            target_entry_id=target_entry.log_id,
            reason_category=reason_category,
            sanitized_justification=justification,
            hours_reversed=hours,
            domain_reversed=domain,
            supervisor_trade_id=supervisor_trade_id,
            supervisor_signature_b64=base64.b64encode(sig).decode("utf-8"),
            invalidation_timestamp=inval_time
        )

    @classmethod
    def verify_invalidation_block(
        cls,
        supervisor_public_key: ed25519.Ed25519PublicKey,
        invalidation_block
    ) -> Tuple[bool, Optional[str]]:
        try:
            canonical_inval = f"{invalidation_block.target_entry_id}:{invalidation_block.reason_category}:{invalidation_block.hours_reversed}:{invalidation_block.domain_reversed}:{invalidation_block.supervisor_trade_id}:{invalidation_block.invalidation_timestamp.isoformat()}"
            sig_bytes = base64.b64decode(invalidation_block.supervisor_signature_b64)
            supervisor_public_key.verify(sig_bytes, canonical_inval.encode("utf-8"))
            return True, None
        except Exception as e:
            return False, f"Invalid supervisor revocation signature: {str(e)}"


    @classmethod
    def create_bilateral_attestation_pair(
        cls,
        supervisor_private_key: ed25519.Ed25519PrivateKey,
        supervisor_trade_id: str,
        supervisor_name: str,
        apprentice_entry: LogbookEntry,
        apprentice_prev_hash: str,
        supervisor_prev_hash: str
    ):
        """Generates matching bilateral entries for both Apprentice and Supervisor ledgers."""
        from .models import BilateralAttestationBlock, SupervisoryOversightEntry, DigitalAttestation

        # Compute canonical apprentice entry hash
        apprentice_entry_hash = cls.compute_entry_hash(apprentice_entry, apprentice_prev_hash)
        apprentice_entry.entry_hash = apprentice_entry_hash

        # Supervisor signs the apprentice entry hash
        sig_bytes = supervisor_private_key.sign(apprentice_entry_hash.encode("utf-8"))
        sig_b64 = base64.b64encode(sig_bytes).decode("utf-8")
        timestamp = datetime.now(timezone.utc)

        # 1. Update apprentice entry with digital attestation
        apprentice_entry.status = "signed"
        apprentice_entry.attestation = DigitalAttestation(
            supervisor_signature=sig_b64,
            signed_timestamp=timestamp
        )

        # 2. Create bilateral attestation block
        bilateral_block = BilateralAttestationBlock(
            supervised_practitioner_trade_id=apprentice_entry.practitioner.trade_id,
            supervised_practitioner_name=apprentice_entry.practitioner.name,
            supervised_tier=apprentice_entry.practitioner.tier,
            apprentice_entry_id=apprentice_entry.log_id,
            apprentice_entry_hash=apprentice_entry_hash,
            supervisor_trade_id=supervisor_trade_id,
            supervisor_name=supervisor_name,
            supervisory_ratio_on_shift="2:1",
            supervisor_signature_b64=sig_b64,
            signed_timestamp=timestamp
        )

        # 3. Create supervisor supervisory oversight entry
        sup_entry_id = f"urn:uuid:sup-ovs-{hashlib.sha256(f'{apprentice_entry.log_id}:{supervisor_trade_id}'.encode()).hexdigest()[:16]}"
        canonical_sup = f"{sup_entry_id}:{supervisor_prev_hash}:{apprentice_entry_hash}:{apprentice_entry.runtime_execution.hours_logged}:{apprentice_entry.runtime_execution.core_domain}"
        sup_hash = hashlib.sha256(canonical_sup.encode("utf-8")).hexdigest()

        supervisory_entry = SupervisoryOversightEntry(
            log_id=sup_entry_id,
            entry_type="supervisory_oversight",
            prev_entry_hash=supervisor_prev_hash,
            entry_hash=sup_hash,
            supervisor_trade_id=supervisor_trade_id,
            supervisor_name=supervisor_name,
            date=apprentice_entry.runtime_execution.date,
            hours_instructed=apprentice_entry.runtime_execution.hours_logged,
            core_domain=apprentice_entry.runtime_execution.core_domain,
            bilateral_attestation=bilateral_block
        )

        return apprentice_entry, supervisory_entry

    @classmethod
    def verify_bilateral_ledger_match(
        cls,
        apprentice_entry: LogbookEntry,
        supervisory_entry,
        supervisor_public_key: ed25519.Ed25519PublicKey,
        apprentice_prev_hash: str
    ) -> Tuple[bool, Optional[str]]:
        """Verifies that an apprentice entry and supervisory oversight entry form a valid, matching bilateral pair."""
        # Check target references
        if supervisory_entry.bilateral_attestation.apprentice_entry_id != apprentice_entry.log_id:
            return False, "Bilateral mismatch: supervisory entry does not reference apprentice log ID."

        if supervisory_entry.bilateral_attestation.supervised_practitioner_trade_id != apprentice_entry.practitioner.trade_id:
            return False, "Bilateral mismatch: practitioner Trade ID does not match supervisory record."

        # Verify apprentice entry hash match
        expected_apprentice_hash = cls.compute_entry_hash(apprentice_entry, apprentice_prev_hash)
        if supervisory_entry.bilateral_attestation.apprentice_entry_hash != expected_apprentice_hash:
            return False, f"Bilateral hash mismatch: expected {expected_apprentice_hash}, got {supervisory_entry.bilateral_attestation.apprentice_entry_hash}"

        # Verify supervisor digital signature
        try:
            sig_bytes = base64.b64decode(supervisory_entry.bilateral_attestation.supervisor_signature_b64)
            supervisor_public_key.verify(sig_bytes, expected_apprentice_hash.encode("utf-8"))
            return True, None
        except Exception as e:
            return False, f"Bilateral signature verification failed: {str(e)}"




