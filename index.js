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
const budgetCollection = client.db("studentLifeDb").collection("budgets");
const capsCollection = client.db("studentLifeDb").collection("caps");
const studyPlannerCollection = client.db("studentLifeDb").collection("studyPlanner");
const questionsCollection = client.db("studentLifeDb").collection("questions");
const studyMaterialsCollection = client.db("studentLifeDb").collection("studyMaterials");
const taskCollection = client.db("studentLifeDb").collection("tasks");

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

                // Authorization check - users can only access their own data
                if (req.user.email !== email) {
                    return res.status(403).send({
                        error: true,
                        message: "Access denied."
                    });
                }

                // Find the user by email and return full record
                const user = await userCollection.findOne({ email });

                if (!user) {
                    return res.status(404).send({
                        error: true,
                        message: "User not found."
                    });
                }

                res.send(user);
            } catch (error) {
                console.error("❌ Error fetching user:", error);
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
                user.role = user.role || 'user';

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

        // ✅ PUT /users/:email - Update user profile information
        app.put('/users/:email', verifyFirebaseToken, async (req, res) => {
            try {
                const email = req.params.email;
                const updateData = req.body;

                // Validate that the authenticated user can only update their own data
                if (req.user.email !== email) {
                    return res.status(403).send({
                        error: true,
                        message: "You can only update your own profile."
                    });
                }

                // Check if user exists
                const existingUser = await userCollection.findOne({ email });
                if (!existingUser) {
                    return res.status(404).send({
                        error: true,
                        message: "User not found."
                    });
                }

                // Validate update data - only allow specific fields to be updated
                const allowedFields = ['name', 'profilePhoto'];
                const updateFields = {};

                for (const field of allowedFields) {
                    if (updateData[field] !== undefined) {
                        updateFields[field] = updateData[field];
                    }
                }

                // Add update timestamp
                updateFields.updatedAt = new Date().toISOString();

                // Update user document
                const result = await userCollection.updateOne(
                    { email },
                    { $set: updateFields }
                );

                if (result.modifiedCount === 0) {
                    return res.status(200).send({
                        success: true,
                        message: "No changes detected."
                    });
                }

                // Fetch and return the updated user
                const updatedUser = await userCollection.findOne({ email });

                return res.status(200).send({
                    success: true,
                    message: "User profile updated successfully.",
                    data: updatedUser
                });

            } catch (error) {
                console.error("❌ Error updating user:", error);
                return res.status(500).send({
                    error: true,
                    message: "Internal Server Error"
                });
            }
        });

        // ✅ DELETE /users/:email - Delete user account (optional)
        app.delete('/users/:email', verifyFirebaseToken, async (req, res) => {
            try {
                const email = req.params.email;

                // Authorization check
                if (req.user.email !== email) {
                    return res.status(403).send({
                        error: true,
                        message: "You can only delete your own account."
                    });
                }

                const result = await userCollection.deleteOne({ email });

                if (result.deletedCount === 0) {
                    return res.status(404).send({
                        error: true,
                        message: "User not found."
                    });
                }

                return res.status(200).send({
                    success: true,
                    message: "User account deleted successfully."
                });

            } catch (error) {
                console.error("❌ Error deleting user:", error);
                return res.status(500).send({
                    error: true,
                    message: "Internal Server Error"
                });
            }
        });


        //********* Schedule related APIs *********

        // GET /schedules - Get all schedules for the logged-in user
        app.get('/schedules', verifyFirebaseToken, async (req, res) => {
            try {
                const email = req.user.email;
                const {
                    search = '',
                    sortBy = 'date',       // default sort
                    order = 'asc',
                    page = 1,
                    limit = 12
                } = req.query;

                const currentPage = parseInt(page) || 1;
                const perPage = parseInt(limit) || 12;

                const query = { createdBy: email };

                // Search by subject (case-insensitive)
                if (search.trim()) {
                    query.subject = { $regex: search.trim(), $options: 'i' };
                }

                // Base cursor
                let cursor = scheduleCollection.find(query);

                // Sort
                const sortOptions = {};

                if (sortBy === 'priority') {
                    // Custom priority sort (High = 1, Low = 3)
                    const priorityMap = { High: 1, Medium: 2, Low: 3 };

                    const schedules = await cursor.toArray();

                    schedules.sort((a, b) => {
                        const aVal = priorityMap[a.priority] || 4;
                        const bVal = priorityMap[b.priority] || 4;
                        return order === 'desc' ? bVal - aVal : aVal - bVal;
                    });

                    const total = schedules.length;
                    const paginated = schedules.slice((currentPage - 1) * perPage, currentPage * perPage);

                    return res.status(200).send({
                        success: true,
                        data: paginated,
                        total,
                        page: currentPage,
                        limit: perPage,
                        totalPages: Math.ceil(total / perPage)
                    });
                } else {
                    // Normal DB-level sorting
                    sortOptions[sortBy] = order === 'desc' ? -1 : 1;
                    cursor = cursor.sort(sortOptions);
                }

                const total = await scheduleCollection.countDocuments(query);
                const schedules = await cursor
                    .skip((currentPage - 1) * perPage)
                    .limit(perPage)
                    .toArray();

                res.status(200).send({
                    success: true,
                    data: schedules,
                    total,
                    page: currentPage,
                    limit: perPage,
                    totalPages: Math.ceil(total / perPage)
                });

            } catch (error) {
                console.error('❌ Error fetching schedules:', error);
                res.status(500).send({ error: true, message: 'Internal Server Error' });
            }
        });

        // GET /schedules/:id - Get a single schedule
        app.get('/schedules/:id', verifyFirebaseToken, async (req, res) => {
            try {
                const { id } = req.params;
                const email = req.user.email;

                const schedule = await scheduleCollection.findOne({ id, createdBy: email });

                if (!schedule) {
                    return res.status(404).send({ success: false, message: "Schedule not found" });
                }

                res.status(200).send(schedule);
            } catch (error) {
                console.error("❌ Error fetching schedule:", error);
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

        // PUT /schedules/:id - Update a schedule by ID
        app.put('/schedules/:id', verifyFirebaseToken, async (req, res) => {
            try {
                const { id } = req.params;
                const email = req.user.email;
                const updatedData = req.body;

                console.log("➡️ Incoming PUT request");
                console.log("📌 ID:", id);
                console.log("📌 Email:", email);
                console.log("📌 Updated Data:", updatedData);

                // 🔥 Remove fields that should not be updated
                delete updatedData._id;
                delete updatedData.createdBy;
                delete updatedData.createdAt;

                // ✅ Filter by id and createdBy
                const filter = { id: id, createdBy: email };

                // Prepare update object
                const updateDoc = { $set: updatedData };

                const result = await scheduleCollection.updateOne(filter, updateDoc);

                console.log("✅ MongoDB update result:", result);

                if (result.matchedCount === 0) {
                    return res.status(404).send({
                        success: false,
                        message: "Schedule not found or unauthorized"
                    });
                }

                res.status(200).send({
                    success: true,
                    message: "Schedule updated successfully"
                });

            } catch (error) {
                console.error("❌ Error updating schedule:", error);
                res.status(500).send({
                    error: true,
                    message: "Internal Server Error"
                });
            }
        });

        // DELETE /schedules/:id - Delete a schedule by ID
        app.delete('/schedules/:id', verifyFirebaseToken, async (req, res) => {
            try {
                const { id } = req.params;
                const email = req.user.email;

                const result = await scheduleCollection.deleteOne({ id: id, createdBy: email });

                if (result.deletedCount === 0) {
                    return res.status(404).send({ success: false, message: "Schedule not found or unauthorized" });
                }

                res.status(200).send({ success: true, message: "Schedule deleted successfully" });
            } catch (error) {
                console.error("❌ Error deleting schedule:", error);
                res.status(500).send({ error: true, message: "Internal Server Error" });
            }
        });


        //********* Budget related APIs *********

        // ✅ GET /budgets
        app.get('/budgets', verifyFirebaseToken, async (req, res) => {
            try {
                const email = req.user.email;
                const transactions = await budgetCollection
                    .find({ createdBy: email })
                    .sort({ createdAt: -1 })
                    .toArray();

                res.status(200).send({ success: true, data: transactions });
            } catch (error) {
                console.error('❌ GET /budgets failed:', error.message);
                res.status(500).send({ success: false, message: 'Internal Server Error' });
            }
        });

        // ✅ Enhanced GET /budgets/history with search, filter, sort, and pagination
        app.get('/budgets/history', verifyFirebaseToken, async (req, res) => {
            try {
                const email = req.user.email;
                const {
                    sortBy = 'date',
                    sortOrder = 'desc',
                    page = 1,
                    limit = 10,
                    search = '',
                    type = 'all'
                } = req.query;

                const currentPage = Math.max(parseInt(page) || 1, 1);
                const perPage = Math.min(parseInt(limit) || 10, 100);

                // ✅ Construct query
                const query = { createdBy: email };

                if (search) {
                    query.$or = [
                        { subject: { $regex: search, $options: 'i' } },
                        { description: { $regex: search, $options: 'i' } }
                    ];
                }

                if (type !== 'all') {
                    query.priority = type === 'income' ? { $ne: 'High' } : 'High';
                }

                // ✅ Map frontend sortBy to MongoDB field
                const sortMap = {
                    date: 'date',
                    amount: 'description', // ⚠️ Only works if amount is in description
                    category: 'subject'
                };

                const sortField = sortMap[sortBy] || 'date';
                const sortDirection = sortOrder === 'asc' ? 1 : -1;

                const total = await budgetCollection.countDocuments(query);

                const transactions = await budgetCollection
                    .find(query)
                    .sort({ [sortField]: sortDirection })
                    .skip((currentPage - 1) * perPage)
                    .limit(perPage)
                    .toArray();

                res.status(200).send({
                    success: true,
                    data: transactions,
                    page: currentPage,
                    limit: perPage,
                    totalPages: Math.ceil(total / perPage),
                    total
                });
            } catch (error) {
                console.error('❌ GET /budgets/history failed:', error.message);
                res.status(500).send({ success: false, message: 'Internal Server Error' });
            }
        });

        // ✅ POST /budgets
        app.post('/budgets', verifyFirebaseToken, async (req, res) => {
            try {
                const transaction = {
                    ...req.body,
                    createdAt: new Date(),
                    createdBy: req.user.email
                };

                const result = await budgetCollection.insertOne(transaction);
                res.status(201).send({ success: true, insertedId: result.insertedId });
            } catch (error) {
                console.error('❌ POST /budgets failed:', error.message);
                res.status(500).send({ success: false, message: 'Internal Server Error' });
            }
        });

        // ✅ GET /budgets/caps
        app.get('/budgets/caps', verifyFirebaseToken, async (req, res) => {
            try {
                const email = req.user.email;
                const caps = await capsCollection.findOne({ createdBy: email });
                res.status(200).send({ success: true, data: caps || { weeklyCap: 500, categoryCaps: {} } });
            } catch (error) {
                console.error('❌ GET /budgets/caps failed:', error.message);
                res.status(500).send({ success: false, message: 'Internal Server Error' });
            }
        });

        // ✅ POST /budgets/caps (create or update caps)
        app.post('/budgets/caps', verifyFirebaseToken, async (req, res) => {
            try {
                const email = req.user.email;
                const { weeklyCap, categoryCaps } = req.body;

                const updateDoc = {
                    $set: {
                        weeklyCap,
                        categoryCaps,
                        updatedAt: new Date(),
                        createdBy: email
                    }
                };

                const result = await capsCollection.updateOne(
                    { createdBy: email },
                    updateDoc,
                    { upsert: true }
                );

                res.status(200).send({ success: true });
            } catch (error) {
                console.error('❌ POST /budgets/caps failed:', error.message);
                res.status(500).send({ success: false, message: 'Internal Server Error' });
            }
        });

        // ✅ DELETE /budgets/:id
        app.delete('/budgets/:id', verifyFirebaseToken, async (req, res) => {
            try {
                const email = req.user.email;
                const { id } = req.params;

                const result = await budgetCollection.deleteOne({
                    _id: new ObjectId(id),
                    createdBy: email, // Optional: ensures users can only delete their own data
                });

                if (result.deletedCount === 1) {
                    res.status(200).send({ success: true, message: 'Transaction deleted' });
                } else {
                    res.status(404).send({ success: false, message: 'Transaction not found' });
                }
            } catch (error) {
                console.error('❌ DELETE /budgets/:id failed:', error.message);
                res.status(500).send({ success: false, message: 'Internal Server Error' });
            }
        });



        //**********Study Planner APIs**********
        app.get('/study-planner', verifyFirebaseToken, async (req, res) => {
            try {
                const email = req.user.email;
                const { search = '', sortBy = 'deadline', order = 'asc', page = 1, limit = 12 } = req.query;
                const currentPage = parseInt(page) || 1;
                const perPage = parseInt(limit) || 12;

                const query = { createdBy: email };
                if (search.trim()) {
                    query.subject = { $regex: search.trim(), $options: 'i' };
                }

                const sortOptions = {};
                if (sortBy === 'priority') {
                    const aggregation = [
                        { $match: query },
                        {
                            $addFields: {
                                priorityValue: {
                                    $switch: {
                                        branches: [
                                            { case: { $eq: ['$priority', 'high'] }, then: 1 },
                                            { case: { $eq: ['$priority', 'medium'] }, then: 2 },
                                            { case: { $eq: ['$priority', 'low'] }, then: 3 },
                                        ],
                                        default: 4,
                                    },
                                },
                            },
                        },
                        { $sort: { priorityValue: order === 'desc' ? -1 : 1 } },
                        { $skip: (currentPage - 1) * perPage },
                        { $limit: perPage },
                        { $project: { priorityValue: 0 } },
                    ];

                    const tasks = await studyPlannerCollection.aggregate(aggregation).toArray();
                    const total = await studyPlannerCollection.countDocuments(query);

                    return res.status(200).send({
                        success: true,
                        data: tasks,
                        total,
                        page: currentPage,
                        limit: perPage,
                        totalPages: Math.ceil(total / perPage),
                    });
                } else {
                    sortOptions[sortBy] = order === 'desc' ? -1 : 1;
                    const tasks = await studyPlannerCollection
                        .find(query)
                        .sort(sortOptions)
                        .skip((currentPage - 1) * perPage)
                        .limit(perPage)
                        .toArray();

                    const total = await studyPlannerCollection.countDocuments(query);
                    res.status(200).send({
                        success: true,
                        data: tasks,
                        total,
                        page: currentPage,
                        limit: perPage,
                        totalPages: Math.ceil(total / perPage),
                    });
                }
            } catch (error) {
                console.error('Error fetching study planner tasks:', error);
                res.status(500).send({ error: true, message: 'Internal Server Error' });
            }
        });

        app.get('/study-planner/:id', verifyFirebaseToken, async (req, res) => {
            try {
                const { id } = req.params;
                const email = req.user.email;
                const task = await studyPlannerCollection.findOne({ id, createdBy: email });
                if (!task) {
                    return res.status(404).send({ success: false, message: 'Task not found' });
                }
                res.status(200).send(task);
            } catch (error) {
                console.error('Error fetching study planner task:', error);
                res.status(500).send({ error: true, message: 'Internal Server Error' });
            }
        });

        app.post('/study-planner', verifyFirebaseToken, async (req, res) => {
            try {
                const task = req.body;

                // Validate required fields
                if (!task.subject || !task.topic || !task.duration || !task.deadline) {
                    return res.status(400).send({ error: true, message: 'Subject, topic, duration, and deadline are required' });
                }
                if (typeof task.duration !== 'number' || task.duration < 5) {
                    return res.status(400).send({ error: true, message: 'Duration must be a number greater than or equal to 5' });
                }
                if (!['low', 'medium', 'high'].includes(task.priority)) {
                    return res.status(400).send({ error: true, message: 'Priority must be low, medium, or high' });
                }

                // Generate custom ID
                task.id = Date.now().toString();
                task.createdAt = new Date().toISOString();
                task.createdBy = req.user.email;

                const result = await studyPlannerCollection.insertOne(task);
                res.status(201).send({
                    success: true,
                    message: 'Study planner task added successfully',
                    insertedId: result.insertedId,
                });
            } catch (error) {
                console.error('Error adding study planner task:', error);
                res.status(500).send({ error: true, message: 'Internal Server Error' });
            }
        });

        app.put('/study-planner/:id', verifyFirebaseToken, async (req, res) => {
            try {
                const { id } = req.params;
                const email = req.user.email;
                const updatedData = req.body;

                // Validate required fields
                if (!updatedData.subject || !updatedData.topic || !updatedData.duration || !updatedData.deadline) {
                    return res.status(400).send({ error: true, message: 'Subject, topic, duration, and deadline are required' });
                }
                if (typeof updatedData.duration !== 'number' || updatedData.duration < 5) {
                    return res.status(400).send({ error: true, message: 'Duration must be a number greater than or equal to 5' });
                }
                if (!['low', 'medium', 'high'].includes(updatedData.priority)) {
                    return res.status(400).send({ error: true, message: 'Priority must be low, medium, or high' });
                }

                delete updatedData._id;
                delete updatedData.createdBy;
                delete updatedData.createdAt;

                const filter = { id, createdBy: email };
                const updateDoc = { $set: updatedData };
                const result = await studyPlannerCollection.updateOne(filter, updateDoc);

                if (result.matchedCount === 0) {
                    return res.status(404).send({ success: false, message: 'Task not found or unauthorized' });
                }

                res.status(200).send({ success: true, message: 'Task updated successfully' });
            } catch (error) {
                console.error('Error updating study planner task:', error);
                res.status(500).send({ error: true, message: 'Internal Server Error' });
            }
        });

        app.delete('/study-planner/:id', verifyFirebaseToken, async (req, res) => {
            try {
                const { id } = req.params;
                const email = req.user.email;
                const result = await studyPlannerCollection.deleteOne({ id, createdBy: email });

                if (result.deletedCount === 0) {
                    return res.status(404).send({ success: false, message: 'Task not found or unauthorized' });
                }

                res.status(200).send({ success: true, message: 'Task deleted successfully' });
            } catch (error) {
                console.error('Error deleting study planner task:', error);
                res.status(500).send({ error: true, message: 'Internal Server Error' });
            }
        });


        //********** Questions related APIs **********

        // GET /questions - Get all questions with pagination and category filtering (accessible to all users)
        app.get('/questions', async (req, res) => {
            try {
                const { category = '', difficulty = '', search = '', sortBy = 'id', order = 'asc', page = 1, limit = 10, createdBy } = req.query;
                const currentPage = parseInt(page) || 1;
                const perPage = parseInt(limit) || 10;

                // Build query based on parameters
                const query = {};

                // If createdBy is specified, filter by that user
                if (createdBy) {
                    query.createdBy = createdBy;
                }

                // If category is specified, filter by category
                if (category && ['html', 'css', 'javascript', 'react'].includes(category.toLowerCase())) {
                    query[`web.${category.toLowerCase()}`] = { $exists: true, $ne: [] };
                }

                // Find all documents that match the query
                const docs = await questionsCollection.find(query).toArray();

                if (!docs || docs.length === 0) {
                    return res.status(200).send({
                        success: true,
                        data: [],
                        total: 0,
                        page: currentPage,
                        limit: perPage,
                        totalPages: 0,
                        message: 'No questions available.',
                    });
                }

                // Combine questions from all matching documents
                let allQuestions = [];
                for (const doc of docs) {
                    const web = doc.web || {};
                    let userQuestions = [];

                    const catLower = category.toLowerCase();
                    if (category && ['html', 'css', 'javascript', 'react'].includes(catLower)) {
                        userQuestions = (web[catLower] || []).map((q) => ({
                            ...q,
                            category: catLower,
                            createdBy: doc.createdBy // Add createdBy info to each question
                        }));
                    } else {
                        userQuestions = Object.entries(web).flatMap(([cat, qs]) =>
                            qs.map((q) => ({
                                ...q,
                                category: cat,
                                createdBy: doc.createdBy // Add createdBy info to each question
                            }))
                        );
                    }
                    allQuestions = allQuestions.concat(userQuestions);
                }

                // Apply difficulty filter
                if (difficulty && ['easy', 'medium', 'high'].includes(difficulty.toLowerCase())) {
                    allQuestions = allQuestions.filter((q) =>
                        q.difficulty && q.difficulty.toLowerCase() === difficulty.toLowerCase()
                    );
                }

                // Apply search filter
                if (search.trim()) {
                    const regex = new RegExp(search.trim(), 'i');
                    allQuestions = allQuestions.filter((q) =>
                        q.question && regex.test(q.question)
                    );
                }

                // Sort questions
                if (sortBy) {
                    allQuestions.sort((a, b) => {
                        let va = a[sortBy];
                        let vb = b[sortBy];
                        if (va === undefined || vb === undefined) return 0;
                        const dir = order === 'asc' ? 1 : -1;
                        if (typeof va === 'string') {
                            return dir * va.localeCompare(vb);
                        }
                        return dir * (va > vb ? 1 : va < vb ? -1 : 0);
                    });
                }

                const total = allQuestions.length;
                const startIndex = (currentPage - 1) * perPage;
                const paginatedQuestions = allQuestions.slice(startIndex, startIndex + perPage);

                res.status(200).send({
                    success: true,
                    data: paginatedQuestions,
                    total,
                    page: currentPage,
                    limit: perPage,
                    totalPages: Math.ceil(total / perPage),
                });
            } catch (error) {
                console.error('❌ Error fetching questions:', error);
                res.status(500).send({ error: true, message: 'Internal Server Error' });
            }
        });
        // POST /questions - Add or update questions
        app.post('/questions', verifyFirebaseToken, async (req, res) => {
            try {
                const email = req.user.email;
                const { web } = req.body;

                if (!web || typeof web !== 'object') {
                    return res.status(400).send({ error: true, message: 'Invalid question data format. Expected "web" object.' });
                }

                const updateDoc = {
                    $set: {
                        web,
                        createdBy: email,
                        updatedAt: new Date().toISOString(),
                    },
                };

                const result = await questionsCollection.updateOne(
                    { createdBy: email },
                    updateDoc,
                    { upsert: true }
                );

                res.status(200).send({
                    success: true,
                    message: result.upsertedId ? 'Questions added successfully' : 'Questions updated successfully',
                    insertedId: result.upsertedId,
                });
            } catch (error) {
                console.error('❌ Error adding/updating questions:', error);
                res.status(500).send({ error: true, message: 'Internal Server Error' });
            }
        });


        app.get('/study-materials', verifyFirebaseToken, async (req, res) => {
            try {
                // Fetch study materials from ALL users
                const studyMaterials = await studyMaterialsCollection.find(
                    {}, // Remove the createdBy filter to get all materials
                    { projection: { web: 1, createdBy: 1, _id: 0 } }
                ).toArray();

                if (!studyMaterials || studyMaterials.length === 0) {
                    return res.status(200).json({
                        success: true,
                        data: {},
                        message: 'No study materials found',
                    });
                }

                // Combine study materials from all users
                const combinedMaterials = {};

                studyMaterials.forEach(userMaterial => {
                    if (userMaterial.web) {
                        // Merge materials from all users
                        Object.keys(userMaterial.web).forEach(subject => {
                            if (!combinedMaterials[subject]) {
                                combinedMaterials[subject] = [];
                            }

                            // Add materials with user info
                            userMaterial.web[subject].forEach(material => {
                                combinedMaterials[subject].push({
                                    ...material,
                                    createdBy: userMaterial.createdBy // Add who created it
                                });
                            });
                        });
                    }
                });

                return res.status(200).json({
                    success: true,
                    data: combinedMaterials,
                });
            } catch (error) {
                console.error('❌ Error fetching study materials:', error);

                return res.status(500).json({
                    error: true,
                    message: error.name === 'MongoError'
                        ? 'Database error occurred'
                        : 'Internal Server Error',
                });
            }
        });


        // ********* Task Planner APIs *********

        // Get all tasks
        app.get('/tasks', verifyFirebaseToken, async (req, res) => {
            try {
                const email = req.user.email;
                const tasks = await taskCollection
                    .find({ createdBy: email })
                    .sort({ date: -1 })
                    .toArray();

                res.status(200).send(tasks);
            } catch (error) {
                console.error('❌ Error fetching tasks:', error);
                res.status(500).send({ error: true, message: 'Internal Server Error' });
            }
        });

        // Get single task by ID
        app.get('/tasks/:id', verifyFirebaseToken, async (req, res) => {
            try {
                const { id } = req.params;
                const email = req.user.email;

                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ error: true, message: 'Invalid task id' });
                }

                const task = await taskCollection.findOne({ _id: new ObjectId(id), createdBy: email });

                if (!task) {
                    return res.status(404).send({ success: false, message: 'Task not found or unauthorized' });
                }

                res.status(200).send(task);
            } catch (error) {
                console.error('❌ Error fetching single task:', error);
                res.status(500).send({ error: true, message: 'Internal Server Error' });
            }
        });

        // Get task statistics
        app.get('/tasks/stats', verifyFirebaseToken, async (req, res) => {
            try {
                const email = req.user.email;

                // Count pending and completed tasks
                const pendingCount = await taskCollection.countDocuments({ createdBy: email, status: "pending" });
                const completedCount = await taskCollection.countDocuments({ createdBy: email, status: "completed" });

                res.status(200).send({
                    success: true,
                    pending: pendingCount,
                    completed: completedCount,
                    total: pendingCount + completedCount
                });
            } catch (error) {
                console.error("❌ Error fetching task stats:", error);
                res.status(500).send({ error: true, message: "Internal Server Error" });
            }
        });

        // Add new task
        app.post('/tasks', verifyFirebaseToken, async (req, res) => {
            try {
                const task = req.body;

                if (!task.title || !task.date || !task.time || !task.duration) {
                    return res.status(400).send({ error: true, message: 'Title, date, time and duration are required' });
                }

                task.id = Date.now().toString();
                task.createdAt = new Date().toISOString();
                task.createdBy = req.user.email;
                task.status = task.status || "pending";
                task.notes = task.notes?.trim() || '';
                task.color = task.color || "#000000";

                const result = await taskCollection.insertOne(task);
                res.status(201).send({
                    success: true,
                    message: 'Task added successfully',
                    insertedId: result.insertedId,
                    data: { ...task, _id: result.insertedId }
                });
            } catch (error) {
                console.error('❌ Error adding task:', error);
                res.status(500).send({ error: true, message: 'Internal Server Error' });
            }
        });

        // Update task (by _id)
        app.put('/tasks/:id', verifyFirebaseToken, async (req, res) => {
            try {
                const { id } = req.params;
                const email = req.user.email;
                const updatedData = req.body;

                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ error: true, message: 'Invalid task id' });
                }

                delete updatedData._id; // prevent overwriting Mongo id

                const filter = { _id: new ObjectId(id), createdBy: email };
                const updateDoc = { $set: { ...updatedData, updatedAt: new Date().toISOString() } };

                const result = await taskCollection.updateOne(filter, updateDoc);

                if (result.matchedCount === 0) {
                    return res.status(404).send({ success: false, message: 'Task not found or unauthorized' });
                }

                res.status(200).send({ success: true, message: 'Task updated successfully' });
            } catch (error) {
                console.error('❌ Error updating task:', error);
                res.status(500).send({ error: true, message: 'Internal Server Error' });
            }
        });

        // Delete task (by _id)
        app.delete('/tasks/:id', verifyFirebaseToken, async (req, res) => {
            try {
                const { id } = req.params;
                const email = req.user.email;

                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ error: true, message: 'Invalid task id' });
                }

                const result = await taskCollection.deleteOne({ _id: new ObjectId(id), createdBy: email });

                if (result.deletedCount === 0) {
                    return res.status(404).send({ success: false, message: 'Task not found or unauthorized' });
                }

                res.status(200).send({ success: true, message: 'Task deleted successfully' });
            } catch (error) {
                console.error('❌ Error deleting task:', error);
                res.status(500).send({ error: true, message: 'Internal Server Error' });
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