# Curemolecules Express & Prisma Backend

This repository represents the full website with an Express/Node.js backend, powered by Prisma ORM.

## Setup Instructions for Local Development

1. Open a terminal in this directory: \`curemolecules-express-prisma\`.
2. Run \`npm install\` to install the necessary packages.
3. Make sure you have your local \`curemolecules\` MySQL database running.
4. The \`.env\` file is already set up to connect to \`mysql://root:@127.0.0.1:3306/curemolecules\`.
5. Generate the Prisma client using: \`npx prisma generate\`.
6. Start the server: \`npm start\`.
7. Your frontend and backend will be accessible at: \`http://localhost:3000\`.


## Deployment to Render (Recommended for Live Database)

Render is great for Node.js + Prisma and offers a simple deployment process.

1. Push this folder to a GitHub repository or connect via the Render dashboard.
2. Select **New Web Service** and choose your repository.
3. Configuration:
   - **Environment:** Node
   - **Build Command:** `npm install && npx prisma generate && npx prisma db push`
   - **Start Command:** `npm start`
4. **Environment Variables**:
   Provide the `DATABASE_URL` referencing your live Cloud database (e.g., Aiven, Render Postgres, PlanetScale MySQL, or DigitalOcean Database). Make sure it ends with your db name.
5. Click **Deploy**. Your website and APIs will be fully accessible!

## Deployment to Vercel (Also works well)

1. Connect your GitHub repository to Vercel.
2. The project has a `vercel.json` configuration which maps the Express.js endpoints for serverless compatibility.
3. In the Vercel Build settings:
   - Framework Preset: **Other**
   - Build Command: `npm install && npx prisma generate && npx prisma db push`
   - Install Command: `npm install`
4. Add your **DATABASE_URL** in the Vercel Environment Variables settings.
5. Deploy.

## Notes
- To change the database to PostgreSQL for production, modify `prisma/schema.prisma` from `provider = "mysql"` to `provider = "postgresql"` before deploying, if your live database is Postgres!
- Enjoy your functional database connection via Prisma!
