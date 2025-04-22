# Inventory Management System Backend

A robust and secure backend system for managing inventory with real-time tracking capabilities. Built with Node.js and Express, this backend provides a comprehensive API for inventory management operations.

## 🚀 Features

### Authentication & Security

- JWT-based authentication system
- Secure password hashing using bcrypt
- Session management
- CORS protection with specific origin whitelisting

### Inventory Management

- Product tracking with detailed attributes
- Real-time stock level monitoring
- Status tracking (available, finished, nearly finished)
- Threshold-based alerts
- Product categorization by size and color

### Database & Performance

- MySQL database integration
- Optimized database queries
- Connection pooling for better performance
- Efficient data indexing
- Scalable architecture

### API Endpoints

- User authentication (register, login)
- Product management (CRUD operations)
- Inventory tracking
- Session management
- Health checks and system status

## 🛠️ Technical Stack

- **Runtime**: Node.js
- **Framework**: Express.js
- **Database**: MySQL
- **Authentication**: JWT, bcrypt
- **Security**: CORS, Environment Variables
- **Deployment**: Vercel (Serverless)

## 🔧 Installation

1. Clone the repository

```bash
git clone [repository-url]
```

2. Install dependencies

```bash
npm install
```

3. Configure environment variables

```bash
cp .env.example .env
```

Edit the `.env` file with your database credentials and JWT secret.

4. Initialize the database

```bash
mysql -u [username] -p < inventory.sql
```

5. Start the server

```bash
npm start
```

## 📊 Performance Optimizations

- **Connection Pooling**: Efficient database connection management
- **Caching**: Optimized data retrieval
- **Indexed Queries**: Fast database operations
- **Compression**: Reduced payload sizes
- **Error Handling**: Graceful degradation

## 🔒 Security Features

- JWT token-based authentication
- Password hashing with bcrypt
- CORS protection
- Environment variable configuration
- Input validation
- SQL injection prevention

## 📝 API Documentation

### Authentication

- `POST /register` - User registration
- `POST /login` - User authentication
- `GET /check-auth` - Authentication status check

### Products

- `GET /products` - List all products
- `POST /products` - Create new product
- `PUT /products/:id` - Update product
- `DELETE /products/:id` - Delete product
- `GET /products/:id` - Get product details

## 🌐 Deployment

The backend is configured for serverless deployment on Vercel, providing:

- Automatic scaling
- Global CDN
- Zero-downtime deployments
- Environment variable management

## 📦 Dependencies

- express: ^4.21.2
- mysql2: ^3.11.5
- bcrypt: ^5.1.1
- jsonwebtoken: ^9.0.2
- cors: ^2.8.5
- dotenv: ^16.4.7
- serverless-http: ^3.2.0

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
