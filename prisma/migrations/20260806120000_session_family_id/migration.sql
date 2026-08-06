-- Refresh-token family for rotation reuse detection (#67)
ALTER TABLE "Session" ADD COLUMN IF NOT EXISTS "familyId" TEXT;
-- Backfill: each existing session is its own family (reuse detection starts on next rotation)
UPDATE "Session" SET "familyId" = "id" WHERE "familyId" IS NULL;
ALTER TABLE "Session" ALTER COLUMN "familyId" SET NOT NULL;

CREATE INDEX IF NOT EXISTS "Session_familyId_idx" ON "Session"("familyId");
CREATE INDEX IF NOT EXISTS "Session_refreshTokenHash_idx" ON "Session"("refreshTokenHash");
