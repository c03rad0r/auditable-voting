import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import {
  createOtpAdmission,
  verifyOtpAndRedeem,
  type OtpAdmissionRecord,
  type OtpAdmissionResult,
} from "./residentOtpBridge";
import { generateOtp, hashOtp, OTP_TTL_MS } from "./otpService";
import { generateQuestionnaireInviteCode, hashQuestionnaireInviteCode } from "./questionnaireInviteCode";

// Mock the Nostr publish function so tests don't hit relays
vi.mock("./questionnaireNostr", () => ({
  publishQuestionnairePrivateInviteStatus: vi.fn().mockResolvedValue({ ok: true }),
}));

import { publishQuestionnairePrivateInviteStatus } from "./questionnaireNostr";

const QUESTIONNAIRE_ID = "election-001";
const COORDINATOR_NPUB = "npub1fakecoordinatorkey0000000000000000000000000000000000000000000000";
const COORDINATOR_NSEC = "nsec1fakecoordinatorkey00000000000000000000000000000000000000000000000";

describe("OtpAdmissionRecord", () => {
  it("record has all required fields populated by createOtpAdmission", async () => {
    const otp = "123456";
    const otpHash = await hashOtp(otp);
    const now = Date.now();

    const record = await createOtpAdmission({
      mastersListNumber: 42,
      otpHash,
      questionnaireId: QUESTIONNAIRE_ID,
      coordinatorNpub: COORDINATOR_NPUB,
      now,
    });

    expect(record.mastersListNumber).toBe(42);
    expect(record.otpHash).toBe(otpHash);
    expect(record.inviteCode).toMatch(/^[0-9a-f]{40}$/); // 20 random bytes → 40 hex chars
    expect(record.inviteCodeHash).toMatch(/^[0-9a-f]{64}$/); // SHA-256 hash
    expect(record.issuedAt).toBe(now);
    expect(record.expiresAt).toBe(now + OTP_TTL_MS);
    expect(record.redeemed).toBe(false);
    expect(record.redeemedAt).toBeUndefined();
  });

  it("inviteCodeHash matches a direct hash of the generated invite code", async () => {
    const otpHash = await hashOtp("999999");
    const now = Date.now();

    const record = await createOtpAdmission({
      mastersListNumber: 1,
      otpHash,
      questionnaireId: QUESTIONNAIRE_ID,
      coordinatorNpub: COORDINATOR_NPUB,
      now,
    });

    const expectedHash = await hashQuestionnaireInviteCode(record.inviteCode);
    expect(record.inviteCodeHash).toBe(expectedHash);
  });
});

describe("verifyOtpAndRedeem", () => {
  beforeEach(() => {
    vi.mocked(publishQuestionnairePrivateInviteStatus).mockClear();
    vi.mocked(publishQuestionnairePrivateInviteStatus).mockResolvedValue({ ok: true });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("returns the invite code on valid OTP verification", async () => {
    const otp = "482910";
    const otpHash = await hashOtp(otp);
    const now = Date.now();

    const record = await createOtpAdmission({
      mastersListNumber: 7,
      otpHash,
      questionnaireId: QUESTIONNAIRE_ID,
      coordinatorNpub: COORDINATOR_NPUB,
      now,
    });

    const result = await verifyOtpAndRedeem({
      mastersListNumber: 7,
      otp,
      record,
      questionnaireId: QUESTIONNAIRE_ID,
      coordinatorNsec: COORDINATOR_NSEC,
    });

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.inviteCode).toBe(record.inviteCode);
      expect(result.inviteCodeHash).toBe(record.inviteCodeHash);
    }
  });

  it("publishes a kind 6426 invite status event on successful verification", async () => {
    const otp = "555555";
    const otpHash = await hashOtp(otp);
    const now = Date.now();

    const record = await createOtpAdmission({
      mastersListNumber: 10,
      otpHash,
      questionnaireId: QUESTIONNAIRE_ID,
      coordinatorNpub: COORDINATOR_NPUB,
      now,
    });

    await verifyOtpAndRedeem({
      mastersListNumber: 10,
      otp,
      record,
      questionnaireId: QUESTIONNAIRE_ID,
      coordinatorNsec: COORDINATOR_NSEC,
    });

    expect(publishQuestionnairePrivateInviteStatus).toHaveBeenCalledTimes(1);
    const callArg = vi.mocked(publishQuestionnairePrivateInviteStatus).mock.calls[0][0];
    expect(callArg.statusEvent.questionnaireId).toBe(QUESTIONNAIRE_ID);
    expect(callArg.statusEvent.codeHash).toBe(record.inviteCodeHash);
    expect(callArg.statusEvent.state).toBe("available");
  });

  it("rejects an expired OTP", async () => {
    const otp = "314159";
    const otpHash = await hashOtp(otp);
    // Issue 20 minutes ago, TTL is 10 minutes → expired
    const issuedAt = Date.now() - 20 * 60 * 1000;

    const record = await createOtpAdmission({
      mastersListNumber: 3,
      otpHash,
      questionnaireId: QUESTIONNAIRE_ID,
      coordinatorNpub: COORDINATOR_NPUB,
      now: issuedAt,
    });

    const result = await verifyOtpAndRedeem({
      mastersListNumber: 3,
      otp,
      record,
      questionnaireId: QUESTIONNAIRE_ID,
      coordinatorNsec: COORDINATOR_NSEC,
    });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toContain("expired");
    }
    expect(publishQuestionnairePrivateInviteStatus).not.toHaveBeenCalled();
  });

  it("rejects an already-redeemed OTP", async () => {
    const otp = "271828";
    const otpHash = await hashOtp(otp);
    const now = Date.now();

    const record = await createOtpAdmission({
      mastersListNumber: 5,
      otpHash,
      questionnaireId: QUESTIONNAIRE_ID,
      coordinatorNpub: COORDINATOR_NPUB,
      now,
    });

    // Mark as already redeemed
    const redeemedRecord: OtpAdmissionRecord = {
      ...record,
      redeemed: true,
      redeemedAt: now + 1000,
    };

    const result = await verifyOtpAndRedeem({
      mastersListNumber: 5,
      otp,
      record: redeemedRecord,
      questionnaireId: QUESTIONNAIRE_ID,
      coordinatorNsec: COORDINATOR_NSEC,
    });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toContain("redeemed");
    }
    expect(publishQuestionnairePrivateInviteStatus).not.toHaveBeenCalled();
  });

  it("rejects an OTP with wrong masters list number", async () => {
    const otp = "112233";
    const otpHash = await hashOtp(otp);
    const now = Date.now();

    const record = await createOtpAdmission({
      mastersListNumber: 99,
      otpHash,
      questionnaireId: QUESTIONNAIRE_ID,
      coordinatorNpub: COORDINATOR_NPUB,
      now,
    });

    const result = await verifyOtpAndRedeem({
      mastersListNumber: 100, // different from record
      otp,
      record,
      questionnaireId: QUESTIONNAIRE_ID,
      coordinatorNsec: COORDINATOR_NSEC,
    });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toContain("masters");
    }
  });

  it("rejects an incorrect OTP", async () => {
    const otp = "654321";
    const otpHash = await hashOtp(otp);
    const now = Date.now();

    const record = await createOtpAdmission({
      mastersListNumber: 15,
      otpHash,
      questionnaireId: QUESTIONNAIRE_ID,
      coordinatorNpub: COORDINATOR_NPUB,
      now,
    });

    const result = await verifyOtpAndRedeem({
      mastersListNumber: 15,
      otp: "000000", // wrong OTP
      record,
      questionnaireId: QUESTIONNAIRE_ID,
      coordinatorNsec: COORDINATOR_NSEC,
    });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toContain("invalid");
    }
  });

  it("marks the record as redeemed after successful verification", async () => {
    const otp = "888888";
    const otpHash = await hashOtp(otp);
    const now = Date.now();

    const record = await createOtpAdmission({
      mastersListNumber: 20,
      otpHash,
      questionnaireId: QUESTIONNAIRE_ID,
      coordinatorNpub: COORDINATOR_NPUB,
      now,
    });

    const result = await verifyOtpAndRedeem({
      mastersListNumber: 20,
      otp,
      record,
      questionnaireId: QUESTIONNAIRE_ID,
      coordinatorNsec: COORDINATOR_NSEC,
    });

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.updatedRecord.redeemed).toBe(true);
      expect(result.updatedRecord.redeemedAt).toBeDefined();
      expect(typeof result.updatedRecord.redeemedAt).toBe("number");
    }
  });

  it("generates a valid invite code (40 hex chars) on successful verification", async () => {
    const otp = "727272";
    const otpHash = await hashOtp(otp);
    const now = Date.now();

    const record = await createOtpAdmission({
      mastersListNumber: 33,
      otpHash,
      questionnaireId: QUESTIONNAIRE_ID,
      coordinatorNpub: COORDINATOR_NPUB,
      now,
    });

    const result = await verifyOtpAndRedeem({
      mastersListNumber: 33,
      otp,
      record,
      questionnaireId: QUESTIONNAIRE_ID,
      coordinatorNsec: COORDINATOR_NSEC,
    });

    expect(result.success).toBe(true);
    if (result.success) {
      // Invite code should be a valid 40-char hex string (same format as generateQuestionnaireInviteCode)
      expect(result.inviteCode).toMatch(/^[0-9a-f]{40}$/);
      // The hash should be the SHA-256 of the invite code
      const expectedHash = await hashQuestionnaireInviteCode(result.inviteCode);
      expect(result.inviteCodeHash).toBe(expectedHash);
    }
  });

  it("different OTP admissions produce different invite codes", async () => {
    const otp1 = "111111";
    const otp2 = "222222";
    const now = Date.now();

    const record1 = await createOtpAdmission({
      mastersListNumber: 1,
      otpHash: await hashOtp(otp1),
      questionnaireId: QUESTIONNAIRE_ID,
      coordinatorNpub: COORDINATOR_NPUB,
      now,
    });

    const record2 = await createOtpAdmission({
      mastersListNumber: 2,
      otpHash: await hashOtp(otp2),
      questionnaireId: QUESTIONNAIRE_ID,
      coordinatorNpub: COORDINATOR_NPUB,
      now,
    });

    expect(record1.inviteCode).not.toBe(record2.inviteCode);
    expect(record1.inviteCodeHash).not.toBe(record2.inviteCodeHash);
  });
});