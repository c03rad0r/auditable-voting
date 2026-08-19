import { OTP_TTL_MS, isOtpExpired, verifyOtp } from "./otpService";
import {
  generateQuestionnaireInviteCode,
  hashQuestionnaireInviteCode,
} from "./questionnaireInviteCode";
import { publishQuestionnairePrivateInviteStatus } from "./questionnaireNostr";
import type { QuestionnairePrivateInviteStatusEvent } from "./questionnaireProtocol";

/**
 * Record linking a resident's OTP admission to a questionnaire invite code.
 * Stored by the coordinator after OTP generation; updated when the OTP is redeemed.
 */
export interface OtpAdmissionRecord {
  mastersListNumber: number;
  otpHash: string;
  inviteCode: string;
  inviteCodeHash: string;
  issuedAt: number;
  expiresAt: number;
  redeemed: boolean;
  redeemedAt?: number;
}

/**
 * Input for creating a new OTP admission record.
 */
export interface CreateOtpAdmissionInput {
  mastersListNumber: number;
  otpHash: string;
  questionnaireId: string;
  coordinatorNpub: string;
  /** Override the issue timestamp (for testing). Defaults to Date.now(). */
  now?: number;
  /** Override the TTL in milliseconds (for testing). Defaults to OTP_TTL_MS. */
  ttlMs?: number;
}

/**
 * Result of verifying an OTP and redeeming the associated invite code.
 */
export type OtpAdmissionResult =
  | {
      success: true;
      inviteCode: string;
      inviteCodeHash: string;
      updatedRecord: OtpAdmissionRecord;
    }
  | {
      success: false;
      error: string;
    };

/**
 * Input for verifying an OTP and redeeming the invite code.
 */
export interface VerifyOtpAndRedeemInput {
  mastersListNumber: number;
  otp: string;
  record: OtpAdmissionRecord;
  questionnaireId: string;
  coordinatorNsec: string;
  relays?: string[];
  /** Override the current time (for testing). Defaults to Date.now(). */
  now?: number;
}

/**
 * Create a new OtpAdmissionRecord by generating a fresh invite code.
 *
 * This is called by the coordinator after generating an OTP for a resident.
 * The invite code is generated using the standard `generateQuestionnaireInviteCode()`
 * function, and its hash is computed using `hashQuestionnaireInviteCode()`.
 *
 * The caller is responsible for publishing the kind 6426 status event — this
 * function only creates the record. Use `verifyOtpAndRedeem` for the full
 * verification + publish flow.
 */
export async function createOtpAdmission(
  input: CreateOtpAdmissionInput,
): Promise<OtpAdmissionRecord> {
  const now = input.now ?? Date.now();
  const ttlMs = input.ttlMs ?? OTP_TTL_MS;

  const inviteCode = generateQuestionnaireInviteCode();
  const inviteCodeHash = await hashQuestionnaireInviteCode(inviteCode);

  return {
    mastersListNumber: input.mastersListNumber,
    otpHash: input.otpHash,
    inviteCode,
    inviteCodeHash,
    issuedAt: now,
    expiresAt: now + ttlMs,
    redeemed: false,
  };
}

/**
 * Verify an OTP against an admission record and, on success, redeem the
 * associated invite code.
 *
 * On successful verification:
 * 1. The OTP is checked against the stored hash (using `verifyOtp`).
 * 2. The masters list number is matched.
 * 3. The OTP is checked for expiry (using `isOtpExpired`).
 * 4. The record is checked for prior redemption.
 * 5. A kind 6426 `QuestionnairePrivateInviteStatusEvent` is published with
 *    the invite code hash, making it available for the blind credential flow.
 * 6. The record is marked as redeemed.
 *
 * After this, the voter uses the returned invite code in the standard blind
 * credential flow — no changes to the existing flow are needed.
 */
export async function verifyOtpAndRedeem(
  input: VerifyOtpAndRedeemInput,
): Promise<OtpAdmissionResult> {
  const now = input.now ?? Date.now();
  const { record, otp, mastersListNumber } = input;

  // 1. Check masters list number matches
  if (mastersListNumber !== record.mastersListNumber) {
    return {
      success: false,
      error: `masters list number mismatch: expected ${record.mastersListNumber}, got ${mastersListNumber}`,
    };
  }

  // 2. Check if already redeemed
  if (record.redeemed) {
    return {
      success: false,
      error: "OTP has already been redeemed",
    };
  }

  // 3. Check expiry
  if (isOtpExpired(record.issuedAt, record.expiresAt - record.issuedAt)) {
    return {
      success: false,
      error: "OTP has expired",
    };
  }

  // 4. Verify OTP against stored hash
  const otpValid = await verifyOtp(otp, record.otpHash);
  if (!otpValid) {
    return {
      success: false,
      error: "invalid OTP",
    };
  }

  // 5. Publish kind 6426 invite status event
  const statusEvent: QuestionnairePrivateInviteStatusEvent = {
    schemaVersion: 1,
    eventType: "questionnaire_private_invite_status",
    questionnaireId: input.questionnaireId,
    codeHash: record.inviteCodeHash,
    state: "available",
    createdAt: now,
    coordinatorPubkey: "", // Will be set by publishQuestionnairePrivateInviteStatus from nsec
  };

  await publishQuestionnairePrivateInviteStatus({
    coordinatorNsec: input.coordinatorNsec,
    statusEvent,
    relays: input.relays,
  });

  // 6. Mark as redeemed
  const updatedRecord: OtpAdmissionRecord = {
    ...record,
    redeemed: true,
    redeemedAt: now,
  };

  return {
    success: true,
    inviteCode: record.inviteCode,
    inviteCodeHash: record.inviteCodeHash,
    updatedRecord,
  };
}