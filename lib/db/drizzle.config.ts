import { defineConfig } from "drizzle-kit";
import path from "path";

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL, ensure the database is provisioned");
}

export default defineConfig({
  schema: path.join(__dirname, "./src/schema/index.ts"),
  dialect: "postgresql",
  dbCredentials: {
    url: process.env.DATABASE_URL,
  },
  // The Flask API (artifacts/flask-api/main.py, init_db) owns the application
  // schema and creates/migrates these tables itself at boot. Exclude them so
  // drizzle-kit push / Replit's deploy migration never diffs against the empty
  // Drizzle schema and proposes dropping them.
  tablesFilter: [
    "!attendance_logs",
    "!employees",
    "!imported_batches",
    "!login_attempts",
    "!orgs",
    "!point_redemptions",
    "!point_resets",
    "!pulse_credentials",
    "!scrape_runs",
    "!shift_swaps",
    "!stores",
    "!users",
  ],
});
