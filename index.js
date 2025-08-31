require('dotenv').config(); // Load environment variables from .env file
const express = require('express'); // Import Express framework
const cors = require('cors'); // Import CORS middleware to handle cross-origin requests
const { MongoClient, ServerApiVersion } = require('mongodb'); // Import MongoDB client and server API version
const { ObjectId } = require('mongodb'); // Import ObjectId to work with MongoDB document IDs
const admin = require("firebase-admin"); // Import Firebase Admin SDK for authentication
// Initialize Firebase Admin SDK with service account key
const decoded = Buffer.from(process.env.FIREBASE_ADMIN_SERVICE_KEY, 'base64').toString('utf8');


// Initialize Firebase Admin SDK
try {
    const serviceAccount = JSON.parse(decoded);

    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
    });

    console.log("Firebase admin initialized");
} catch (error) {
    console.error("Failed to parse service account key:", error);
}



// Initialize Express application
const app = express();
const port = process.env.PORT || 3000; // Use port from environment or fallback to 3000

// Middleware setup
app.use(cors()); // Enable CORS for all routes
app.use(express.json()); // Enable JSON body parsing for incoming requests

// Root route - simple health check endpoint
app.get('/', (req, res) => {
    res.send('😲 Wow !!! Student Life Pro ❤️ Server is Successfully 😁 running🔥');
});

// MongoDB client initialization with server API options for stable behavior
const client = new MongoClient(process.env.DB_URI, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    },
});


// Reference collections from database

const userCollection = client.db("studentLifeDb").collection("users");
const scheduleCollection = client.db("studentLifeDb").collection("schedules");



// ✅ Middleware to verify Firebase ID token and extract user info
const verifyFirebaseToken = async (req, res, next) => {
    const authHeader = req.headers?.authorization;

    // Check if the Authorization header exists and starts with 'Bearer '
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).send({ error: true, message: 'Unauthorized access' });
    }

    // Extract the token from the header
    const idToken = authHeader.split(' ')[1];

    try {
        // Verify the token using Firebase Admin SDK
        const decodedToken = await admin.auth().verifyIdToken(idToken);

        // If token doesn't include email, fetch full user record from Firebase
        if (!decodedToken.email) {
            const userRecord = await admin.auth().getUser(decodedToken.uid);

            // Use email directly if available
            if (userRecord.email) {
                decodedToken.email = userRecord.email;
            } else {
                // Fallback: try to get email from the provider data (e.g., Google)
                const googleProvider = userRecord.providerData?.find(
                    provider => provider.providerId === 'google.com'
                );

                if (googleProvider?.email) {
                    decodedToken.email = googleProvider.email;
                } else {
                    // If email still not found, reject the request
                    return res.status(400).send({
                        error: true,
                        message: 'No email associated with this account'
                    });
                }
            }
        }

        // Attach user info to the request object for downstream middlewares/routes
        req.user = decodedToken;
        next(); // Proceed to the next middleware
    } catch (error) {
        // Handle invalid or expired token
        console.error('Error verifying Firebase ID token:', error);
        res.status(401).send({ error: true, message: 'Unauthorized access' });
    }
};


// Main async function to run server logic after connecting to DB
async function run() {
    try {

        // ********* User related APIs *********

        // ✅ GET /users/:email - Fetch a specific user by email
        app.get('/users/:email', verifyFirebaseToken, async (req, res) => {
            try {
                const email = req.params.email;

                // Find the user by email and return full record
                const user = await userCollection.findOne({ email });

                res.send(user);
            } catch (error) {
                console.error("❌ Error checking user existence:", error);
                res.status(500).send({ error: true, message: "Internal Server Error" });
            }
        });

        // ✅ POST /users - Add a new user or update an existing user's info
        app.post('/users', async (req, res) => {
            try {
                const user = req.body;

                // Email is mandatory for user creation
                if (!user?.email) {
                    return res.status(400).send({ error: true, message: "Email is required." });
                }

                // Check if user already exists
                const existingUser = await userCollection.findOne({ email: user.email });

                if (existingUser) {
                    // If user exists, update lastLogin and changed fields
                    const updateData = {
                        lastLogin: new Date().toISOString(),
                    };

                    // Update name if it changed
                    if (user.name && user.name !== existingUser.name) {
                        updateData.name = user.name;
                    }

                    // Update profile photo if it changed
                    if (user.profilePhoto && user.profilePhoto !== existingUser.profilePhoto) {
                        updateData.profilePhoto = user.profilePhoto;
                    }

                    // Update user document
                    await userCollection.updateOne(
                        { email: user.email },
                        { $set: updateData }
                    );

                    return res.status(200).send({
                        success: true,
                        message: "User already exists. Info updated.",
                    });
                }

                // If user is new, set creation and login timestamps
                user.createdAt = user.createdAt || new Date().toISOString();
                user.lastLogin = new Date().toISOString();

                // Insert new user
                const result = await userCollection.insertOne(user);

                return res.status(201).send({
                    success: true,
                    message: "User created successfully.",
                    insertedId: result.insertedId,
                });

            } catch (error) {
                console.error("❌ Error inserting/updating user:", error);
                return res.status(500).send({ error: true, message: "Internal Server Error" });
            }
        });


        //********* Schedule related APIs *********

        // ✅ GET /schedules - Fetch all schedules
        app.get('/schedules', verifyFirebaseToken, async (req, res) => {
            try {
                const schedules = await scheduleCollection.find().toArray();
                res.send(schedules);
            } catch (error) {
                console.error("❌ Error fetching schedules:", error);
                res.status(500).send({ error: true, message: "Internal Server Error" });
            }
        });

        // ✅ POST /schedules - Add a new class schedule
        app.post('/schedules', verifyFirebaseToken, async (req, res) => {
            try {
                const schedule = req.body;

                // Add createdAt and createdBy (email) fields
                schedule.createdAt = new Date().toISOString();
                schedule.createdBy = req.user.email;

                const result = await scheduleCollection.insertOne(schedule);

                res.status(201).send({
                    success: true,
                    message: 'Class schedule added successfully',
                    insertedId: result.insertedId
                });
            } catch (error) {
                console.error("❌ Error adding schedule:", error);
                res.status(500).send({ error: true, message: "Internal Server Error" });
            }
        });



        console.log("✅ Connected to MongoDB!");
    } catch (err) {
        console.error('❌ MongoDB connection error:', err);
    }
}

// Run the async server setup function
run().catch(console.dir);

// Start Express server and listen on the configured port
app.listen(port, () => {
    console.log(`🚀 Server listening on port ${port}`);
});