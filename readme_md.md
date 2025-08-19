# User Management API

A comprehensive user management system with authentication, authorization, and admin features built with Node.js and Express.

## Features

- **User Authentication**: JWT-based authentication system
- **User Registration**: Secure user account creation
- **Profile Management**: Users can update their profiles and change passwords
- **Role-Based Access Control**: Admin and user roles with different permissions
- **Admin Dashboard**: User management, statistics, and administrative controls
- **Security Features**: Rate limiting, password hashing, input validation
- **Comprehensive API**: RESTful endpoints with proper HTTP status codes
- **Data Validation**: Input validation using express-validator
- **Error Handling**: Comprehensive error handling and user-friendly messages

## Default Admin Account

- **Email**: `admin@example.com`
- **Password**: `admin123`

> ⚠️ **Important**: Change the default admin password in production!

## Prerequisites

Before installation, ensure you have the following installed on your system:

- **Node.js** (version 16.0.0 or higher)
- **npm** (version 8.0.0 or higher)
- **Git** (for cloning the repository)

## Installation Instructions

### Windows

#### Option 1: Using Command Prompt/PowerShell

1. **Install Node.js**
   - Download from [https://nodejs.org/](https://nodejs.org/)
   - Run the installer and follow the setup wizard
   - Verify installation:
   ```cmd
   node --version
   npm --version
   ```

2. **Clone and setup the project**
   ```cmd
   git clone <repository-url>
   cd user-management-api
   npm install
   ```

3. **Create environment file**
   ```cmd
   copy .env.example .env
   ```

```

## Environment Configuration

Create a `.env` file in the root directory with the following variables:

```env
# Server Configuration
PORT=3000
NODE_ENV=development

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-in-production-use-long-random-string
JWT_EXPIRES_IN=24h

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
AUTH_RATE_LIMIT_MAX_REQUESTS=5
```

## Running the Application

### Development Mode

```bash
# Install nodemon globally (optional)
npm install -g nodemon

# Start the server in development mode
npm run dev
```

### Production Mode

```bash
# Start the server
npm start
```

The server will start on `http://localhost:3000` (or the port specified in your `.env` file).

## API Endpoints

### Health Check
- `GET /api/health` - Check API status

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - User login
- `GET /api/auth/me` - Get current user profile
- `PUT /api/auth/profile` - Update user profile
- `POST /api/auth/change-password` - Change password

### Admin Endpoints (Requires Admin Role)
- `GET /api/admin/users` - Get all users (paginated)
- `GET /api/admin/users/:id` - Get user by ID
- `PUT /api/admin/users/:id` - Update user
- `DELETE /api/admin/users/:id` - Delete user
- `GET /api/admin/stats` - Get system statistics

## Testing with Postman

### Import the Collection

1. Open Postman
2. Click "Import" button
3. Select the `User Management API.postman_collection.json` file
4. The collection will be imported with all endpoints and tests

### Running Tests

1. **Individual Tests**: Click on any request and hit "Send"
2. **Collection Tests**: Use the Collection Runner to run all tests
3. **Automated Tests**: Each request includes automated tests that validate responses

### Collection Variables

The collection uses these variables:
- `baseUrl`: API base URL (default: `http://localhost:3000`)
- `authToken`: JWT token (automatically set after login)
- `userId`: User ID (automatically set after registration)
- `testEmail`: Test user email

## Testing Flow

1. **Health Check**: Verify the API is running
2. **Register User**: Create a test user account
3. **Login User**: Authenticate and get JWT token
4. **Profile Operations**: Test profile viewing and updating
5. **Admin Login**: Login with admin credentials
6. **Admin Operations**: Test user management and statistics
7. **Error Cases**: Test validation and error handling

## Rate Limiting

The API implements rate limiting for security:

- **General endpoints**: 100 requests per 15 minutes per IP
- **Authentication endpoints**: 5 requests per 15 minutes per IP

## Security Features

- **Password Hashing**: Bcrypt with salt rounds
- **JWT Authentication**: Secure token-based authentication
- **Input Validation**: Express-validator for request validation
- **Rate Limiting**: Protection against brute force attacks
- **CORS**: Cross-origin resource sharing configuration
- **Helmet**: Security headers middleware
- **Role-Based Access**: Admin and user role separation

## Project Structure

```
user-management-api/
├── server.js                 # Main application file
├── package.json              # Project dependencies
├── .env.example             # Environment variables template
├── .env                     # Environment variables (create this)
├── README.md                # This file
└── User Management API.postman_collection.json  # Postman collection
```

## Development Guidelines

### Code Style

- Use ES6+ features
- Follow RESTful API conventions
- Implement proper error handling
- Add input validation for all endpoints
- Use middleware for common functionality

### Adding New Features

1. Create new routes following the existing pattern
2. Add input validation using express-validator
3. Implement proper error handling
4. Add corresponding Postman tests
5. Update API documentation

## Troubleshooting

### Common Issues

1. **Port already in use**
   ```
   Error: listen EADDRINUSE :::3000
   ```
   **Solution**: Change the PORT in your `.env` file or kill the process using the port

2. **Node.js version issues**
   ```
   Error: Node.js version X.X.X is not supported
   ```
   **Solution**: Update Node.js to version 16.0.0 or higher

3. **Permission errors (Linux/macOS)**
   ```
   Error: EACCES: permission denied
   ```
   **Solution**: Use `sudo` for global npm installs or configure npm to use a different directory

4. **Module not found errors**
   ```
   Error: Cannot find module 'express'
   ```
   **Solution**: Run `npm install` to install dependencies

### Getting Help

If you encounter issues:

1. Check that all prerequisites are installed
2. Verify your `.env` file configuration
3. Check the server logs for error messages
4. Ensure the port is not in use by another application

## API Response Format

All API responses follow this format:

```json
{
  "success": boolean,
  "message": "string",
  "data": object,
  "errors": array (optional)
}
```

## Production Deployment

### Before Deploying

1. **Change default admin password**
2. **Set strong JWT_SECRET**
3. **Configure proper rate limits**
4. **Set NODE_ENV=production**
5. **Implement proper database (currently uses in-memory storage)**
6. **Add HTTPS**
7. **Configure logging**

### Recommended Production Setup

- Use a proper database (MongoDB, PostgreSQL, MySQL)
- Implement Redis for session storage
- Add comprehensive logging (Winston)
- Set up monitoring (PM2, New Relic)
- Use reverse proxy (Nginx)
- Implement backup strategies

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Changelog

### Version 1.0.0
- Initial release
- User authentication and authorization
- Admin user management
- Comprehensive API documentation
- Postman collection with automated tests