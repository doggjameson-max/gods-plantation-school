# God's Plantation School Ikirun — Complete School Management Portal

## Authentication
This version includes real server-side authentication with secure password hashing, session tokens, and role-based access for **Admin, Teacher and Parent**.

### Initial administrator
On the first server start, the application creates:
- Username: `admin`
- Password: `Admin@12345`

**Change the administrator password immediately after the first login.** You can also set `ADMIN_INITIAL_PASSWORD` before the first start to choose a different initial password.

### Admin functions
The administrator can create, activate and deactivate Teacher and Parent accounts from **User Accounts**. Each Teacher account is linked to a staff record, and each Parent account is linked to a parent/guardian record.

### Teacher access
Teachers can access the dashboard, students, attendance, results and lesson plans. Teacher data is restricted by the classes assigned to their staff record.

### Parent access
Parents see their linked child/children, attendance, results, lessons and relevant fee/payment information. Parents cannot modify school records.

## Render deployment
Build command: `npm install`
Start command: `npm start`

Recommended environment variables:
- `ADMIN_INITIAL_PASSWORD` — only needed on first database creation.
- `ADMIN_KEY` — legacy/admin sync compatibility key.
- `DATA_DIR=/var/data` when using a Render persistent disk.

Attach a persistent disk for production so the SQLite database survives redeployments.
