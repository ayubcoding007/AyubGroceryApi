AyubGrocery – Backend:-

The backend of AyubGrocery is built using Node.js and Express.js following a RESTful API architecture. 
It handles authentication, product management, cart operations, and order processing for 
the grocery e-commerce system. The backend is responsible for securely managing user data, 
storing products, and handling all business logic between the client and the database.

This project demonstrates practical backend development skills such as JWT-based authentication, 
role-based access control (User & Seller), environment variable security, MongoDB integration, 
and structured API design. The system is designed to be secure, scalable, and easy to maintain.

Technologies Used:--

Node.js
Express.js
MongoDB (Mongoose ODM)
JWT (JSON Web Token)
bcrypt (Password Hashing)
dotenv (Environment Variables)
CORS
Cookie-parser

.env:--

PORT=5000
MONGO_URI=yourdatabaseurl
JWT_SECRET=andsjhgihq#wheg$7

# NODE_ENV=development ---for local devlopment 
NODE_ENV=production

#admin credentials
SELLER_EMAIL="abc@xyz.com"
SELLER_PASSWORD="abc123"

# cloudinary 
CLOUDINARY_CLOUD_NAME="your_"
CLOUDINARY_API_KEY="your_"
CLOUDINARY_API_SECRET="your_"
