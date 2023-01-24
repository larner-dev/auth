CREATE TABLE "credentials" (
    "id" serial,
    "created_at" timestamp with time zone NOT NULL DEFAULT NOW(),
    "user_id" varchar NOT NULL,
    "type" varchar NOT NULL,
    "secret" text NOT NULL,
    "expires_at" timestamp with time zone DEFAULT NULL,
    PRIMARY KEY ("id")
);

CREATE INDEX "credentials_user_id_type" ON "credentials"("user_id","type");
CREATE INDEX "expires_at" ON "credentials"("expires_at");
