# Candidate Onboarding System

## Deployment on Railway

### Environment Variables Required

Add the following environment variables in your Railway project dashboard:

1. **Database**
   - `DATABASE_URL` - RDS PostgreSQL connection string

2. **AWS S3**
   - `AWS_ACCESS_KEY_ID` - Your AWS access key
   - `AWS_SECRET_ACCESS_KEY` - Your AWS secret key
   - `AWS_S3_BUCKET` - Your S3 bucket name
   - `AWS_REGION` - AWS region (e.g., us-east-1)

3. **Application**
   - `SECRET_KEY` - Flask secret key
   - `DEBUG` - Set to `False` in production

4. **Email**
   - `MAIL_SERVER` - SMTP server
   - `MAIL_PORT` - SMTP port (usually 587)
   - `MAIL_USE_TLS` - `True`
   - `MAIL_USERNAME` - Your email
   - `MAIL_PASSWORD` - Your email password/app password
   - `MAIL_DEFAULT_SENDER` - Default sender email

### Default Admin Account

After deployment, the system automatically creates a default admin account:
- **Email**: admin@company.com
- **Password**: Admin@123

**Important**: Change the default password after first login.