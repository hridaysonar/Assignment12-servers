const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const admin = require("firebase-admin");

// Load environment variables from .env file
dotenv.config();

const stripe = require('stripe')(process.env.PAYMENT_GATEWAY_KEY);

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());


const decodedKey = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8');
const serviceAccount = JSON.parse(decodedKey);

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.8j2b4rj.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;



// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        // await client.connect();

        const db = client.db('parcelDB'); // database name
        const usersCollection = db.collection('users');
        const parcelsCollection = db.collection('parcels');
        const addadmins = db.collection('addadmin');
        const amounts = db.collection('SendParcel');
        const agentRequestsCollection = db.collection('agentRequests'); 
// djdjjdj
        const Application = db.collection('Application');
        const trackingsCollection = db.collection("trackings");
        const paymentsCollection = db.collection('payments');
        const ridersCollection = db.collection('riders');
const reviewsCollection = db.collection('reviews');

        // custom middlewares
        const verifyFBToken = async (req, res, next) => {
            const authHeader = req.headers.authorization;
            if (!authHeader) {
                return res.status(401).send({ message: 'unauthorized access' })
            }
            const token = authHeader.split(' ')[1];
            if (!token) {
                return res.status(401).send({ message: 'unauthorized access' })
            }

            // verify the token
            try {
                const decoded = await admin.auth().verifyIdToken(token);
                req.decoded = decoded;
                next();
            }
            catch (error) {
                return res.status(403).send({ message: 'forbidden access' })
            }
        }

        const verifyAdmin = async (req, res, next) => {
            const email = req.decoded.email;
            const query = { email }
            const user = await usersCollection.findOne(query);
            if (!user || user.role !== 'admin') {
                return res.status(403).send({ message: 'forbidden access' })
            }
            next();
        }

        const verifyRider = async (req, res, next) => {
            const email = req.decoded.email;
            const query = { email }
            const user = await usersCollection.findOne(query);
            if (!user || user.role !== 'rider') {
                return res.status(403).send({ message: 'forbidden access' })
            }
            next();
        }

        // my postede st 
        // Server-side example (you should check if categories is an array)

app.post('/reviews', async (req, res) => {
  const review = req.body;
  
  if (!review.parcelId || !review.review || !review.rating) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  try {
    const result = await reviewsCollection.insertOne({
      ...review,
      createdAt: new Date(),
    });

    res.status(201).json({
      message: 'Review submitted successfully',
      reviewId: result.insertedId,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to submit review' });
  }
});
// Node.js (Express)
// app.get('/reviews', async (req, res) => {
//   const parcelId = req.query.parcelId;
//   const page = parseInt(req.query.page) || 1;
//   const limit = parseInt(req.query.limit) || 5;
//   const skip = (page - 1) * limit;

//   const query = parcelId ? { parcelId } : {};

//   try {
//     const reviews = await reviewsCollection
//       .find(query)
//       .sort({ createdAt: -1 })
//       .skip(skip)
//       .limit(limit)
//       .toArray();

//     res.status(200).json({ reviews });
//   } catch (error) {
//     console.error('Failed to fetch reviews:', error);
//     res.status(500).json({ error: 'Failed to fetch reviews' });
//   }
// });

require('dotenv').config()
const express = require('express')
const cors = require('cors')
const cookieParser = require('cookie-parser')
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb')
const jwt = require('jsonwebtoken')
const FormData = require("form-data");
const axios = require('axios');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY)


const port = process.env.PORT || 3000
const app = express()
app.use(express.json({ limit: "10mb" }));
// middleware
const corsOptions = {
    origin: ['http://localhost:5173', 'http://localhost:5173/'],
    credentials: true,
    optionSuccessStatus: 200,
}
app.use(cors(corsOptions))

app.use(express.json())
app.use(cookieParser())

const verifyToken = async (req, res, next) => {
    const token = req.cookies?.token

    if (!token) {
        return res.status(401).send({ message: 'unauthorized access' })
    }
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
            // console.log(err)
            return res.status(401).send({ message: 'unauthorized access' })
        }
        req.user = decoded
        // console.log(req?.user);

        next()
    })
}



// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(process.env.MONGODB_URI, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    },
})
async function run() {
    try {
        const db = client.db('assignment-12')
        const usersCollection = db.collection('users')
        const policiesCollection = db.collection('policies')
        const applicationsCollection = db.collection('applications')
        const reviewsCollection = db.collection('reviews')
        const agentsCollection = db.collection('agents')
        const dataForAgentsCollection = db.collection('dataForAgents')
        const paymentInfoCollection = db.collection('paymentsInfo')
        const claimRequestsCollection = db.collection("claimRequests");
        const blogsCollection = db.collection("blogs");
        const newsletterSubscribersCollection = db.collection('newsletterSubscribers')
        // Generate jwt token
        app.post('/jwt', async (req, res) => {
            const email = req.body
            const token = jwt.sign(email, process.env.ACCESS_TOKEN_SECRET, {
                expiresIn: '365d',
            })
            res
                .cookie('token', token, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
                })
                .send({ success: true })
        })


        // Logout


        app.get('/logout', async (req, res) => {
            try {
                res
                    .clearCookie('token', {
                        maxAge: 0,
                        secure: process.env.NODE_ENV === 'production',
                        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
                    })
                    .send({ success: true })
            } catch (err) {
                res.status(500).send(err)
            }
        })



        app.get('/policies', async (req, res) => {
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 9;
            const category = req.query.category;
            const search = req.query.search;

            const query = {};

            // Filter by category (optional)
            if (category) {
                query.category = category;
            }

            // Search by title or description using regex
            if (search) {
                query.$or = [
                    { title: { $regex: search, $options: 'i' } },
                    { description: { $regex: search, $options: 'i' } }
                ];
            }

            const total = await policiesCollection.countDocuments(query);
            const policies = await policiesCollection
                .find(query)
                .skip((page - 1) * limit)
                .limit(limit)
                .toArray();

            res.send({ policies, total });
        });


        //post api for poliies
        app.post('/policies', async (req, res) => {
            const newPolicy = req.body;
            // console.log(newPolicy);

            const result = await policiesCollection.insertOne(newPolicy)
            res.send(result)
        })

        // Make sure you have this import at the top of your backend file if you're using MongoDB's native driver


        app.patch('/policyUpdate/:id', verifyToken, async (req, res) => {
            const id = req.params.id;
            const updatedPolicyData = { ...req.body };

            // ❌ Delete _id if it exists to avoid immutable error
            delete updatedPolicyData._id;

            const filter = { _id: new ObjectId(id) };

            const updateDoc = {
                $set: updatedPolicyData
            };

            try {
                const result = await policiesCollection.updateOne(filter, updateDoc);
                res.send(result);
            } catch (error) {
                // console.error("Update failed:", error);
                res.status(500).send({ error: error.message });
            }
        });

        // DELETE a policy by ID
        app.delete('/policy/:id', async (req, res) => {
            const id = req.params.id
            const result = await policiesCollection.deleteOne({ _id: new ObjectId(id) })
            res.send(result)

        });



        app.get('/policies/:id', async (req, res) => {
            const id = req.params.id
            // console.log(id);
            const result = await policiesCollection.findOne({ _id: new ObjectId(id) })
            res.send(result)
        })

        //user applications post


        app.post("/api/upload-image", async (req, res) => {
            try {
                const { imageBase64 } = req.body;
                if (!imageBase64) {
                    return res.status(400).json({ error: "Image data is required" });
                }

                const formData = new FormData();
                formData.append("file", imageBase64);
                formData.append("upload_preset", process.env.CLOUDINARY_UPLOAD_PRESET);

                const response = await axios.post(
                    `https://api.cloudinary.com/v1_1/${process.env.CLOUDINARY_CLOUD_NAME}/image/upload`,
                    formData,
                    {
                        headers: formData.getHeaders(),
                    }
                );

                res.json({ url: response.data.secure_url });
            } catch (error) {
                // console.error("Upload error:", error.response?.data || error.message || error);
                res.status(500).json({ error: "Image upload failed" });
            }
        });
        app.post('/payments', verifyToken, async (req, res) => {
            const payment = req.body; // This 'payment' object comes from the frontend (paymentInfo)


            const insertResult = await paymentInfoCollection.insertOne(payment);

            const query = { _id: new ObjectId(payment.applicationId) };
            const updateDoc = {
                $set: {
                    paymentStatus: 'Paid'

                }
            };
            const updateApplicationResult = await applicationsCollection.updateOne(query, updateDoc);

            // Send back the results of both operations
            res.send({ insertResult, updateApplicationResult });
        });


        app.get('/payments', async (req, res) => {
            const result = await paymentInfoCollection.find().toArray()
            res.send(result)
        })






        app.post('/create-payment-intent', verifyToken, async (req, res) => {
            const { amount } = req.body; // amount should be in cents
            const premiumAmount = parseInt(amount * 100); // Convert to cents and ensure integer

            if (isNaN(premiumAmount) || premiumAmount <= 0) {
                return res.status(400).send({ message: 'Invalid amount provided.' });
            }

            try {
                const paymentIntent = await stripe.paymentIntents.create({
                    amount: premiumAmount,
                    currency: 'usd', // Or your desired currency
                    payment_method_types: ['card'],
                });
                res.send({ clientSecret: paymentIntent.client_secret });
            } catch (error) {
                // console.error('Error creating payment intent:', error);
                res.status(500).send({ message: 'Failed to create payment intent', error: error.message });
            }
        });


        app.get('/claims/user/:email', async (req, res) => {
            try {
                const userEmail = req.params.email;
                const query = { customerEmail: userEmail };
                const claims = await claimRequestsCollection.find(query).toArray();
                res.send(claims);
            } catch (error) {
                // console.error("Error fetching claims by user email:", error);
                res.status(500).send({ message: "Internal Server Error" });
            }
        });

        app.patch('/claims/status/:id', verifyToken, async (req, res) => {
            try {
                const claimId = req.params.id;
                const { status, feedback } = req.body; // Ensure 'feedback' is also destructured

                // console.log(`Received request to update claim ID: ${claimId} to status: ${status}`);
                if (status === 'Rejected') {
                    // console.log(`Rejection feedback: ${feedback}`);
                }

                let updateDoc = {
                    $set: {
                        claimStatus: status,
                        // Add current time for status update or clearance date
                        lastUpdated: new Date()
                    }
                };

                // Only add feedback if status is 'Rejected'
                if (status === 'Rejected') {
                    updateDoc.$set.agentFeedback = feedback;
                } else {
                    // Optionally remove feedback if status changes from Rejected to Approved/Pending
                    updateDoc.$unset = { agentFeedback: "" };
                }

                const result = await claimRequestsCollection.updateOne(
                    { _id: new ObjectId(claimId) },
                    updateDoc
                );

                // console.log("MongoDB update result:", result);

                if (result.matchedCount === 0) {
                    return res.status(404).send({ message: "Claim not found." });
                }
                if (result.modifiedCount === 0) {
                    // If matched but not modified, it means the status was already the requested status
                    return res.status(200).send({ message: `Claim status already set to ${status}. No change needed.` });
                }

                res.send({ message: `Claim status updated to ${status} successfully!` });

            } catch (error) {
                // console.error("Error in /claims/status/:id PATCH route:", error); // This will show in your server logs
                // Handle specific errors if known
                if (error.name === 'CastError' || error.name === 'BSONTypeError') { // Invalid ObjectId
                    return res.status(400).send({ message: "Invalid claim ID format." });
                }
                // Generic 500 for other unexpected errors
                res.status(500).send({ message: "Internal Server Error during claim status update." });
            }
        });

        app.get('/claims/agent/:email', verifyToken, async (req, res) => {
            try {
                const agentEmail = req.params.email;
                // Ensure the email in the token matches the requested email for security
                if (req.user.email !== agentEmail) {
                    return res.status(403).send({ message: "Forbidden: You can only view claims assigned to your email." });
                }

                const query = { agentEmail: agentEmail }; // Filter by agentEmail
                const claims = await claimRequestsCollection.find(query).toArray();
                res.send(claims);
            } catch (error) {
                // console.error("Error fetching claims by agent email:", error);
                res.status(500).send({ message: "Internal Server Error" });
            }
        });
        // 3. POST /claimRequests - Submit a new claim request
        // This route receives claim data from the frontend and saves it
        app.post('/claimRequests', verifyToken, async (req, res) => {
            try {
                const claimData = req.body;
                // Ensure initial status is 'Pending' for new claims
                claimData.claimStatus = 'Pending';
                claimData.claimedAt = new Date().toISOString(); // Record submission time

                // Basic validation (you might want more robust validation)
                if (!claimData.applicationId || !claimData.customerEmail || !claimData.reason) {
                    return res.status(400).send({ message: "Missing required claim data." });
                }

                const result = await claimRequestsCollection.insertOne(claimData);
                res.status(201).send({
                    message: "Claim request submitted successfully!",
                    insertedId: result.insertedId,
                });
            } catch (error) {
                // console.error("Error submitting claim request:", error);
                res.status(500).send({ message: "Internal Server Error" });
            }
        });



        // app.get('/blogs', async (req, res) => {
        //     try {
        //         const blogs = await blogsCollection.find().toArray();
        //         res.send(blogs);
        //     } catch (error) {
        //         // console.error("Error fetching all blogs:", error);
        //         res.status(500).send({ message: "Internal Server Error" });
        //     }
        // });
        // In your Node.js/Express backend file where you define routes

        app.get('/blogs', async (req, res) => {
            try {
                let query = {}; // You can add filtering criteria here if needed in the future

                // 1. Implement Sorting
                let sortCriteria = { publishDate: -1 }; // Default sort: latest first (descending)
                if (req.query.sort) {
                    // Example: sort=-publishDate (for descending) or sort=publishDate (for ascending)
                    const sortField = req.query.sort.replace('-', ''); // Remove '-' for field name
                    const sortOrder = req.query.sort.startsWith('-') ? -1 : 1; // -1 for descending, 1 for ascending
                    sortCriteria = { [sortField]: sortOrder };
                }

                // Start building the MongoDB query
                let cursor = blogsCollection.find(query);

                // Apply sorting
                cursor = cursor.sort(sortCriteria);

                // 2. Implement Limiting
                if (req.query.limit) {
                    const limit = parseInt(req.query.limit, 10);
                    if (!isNaN(limit) && limit > 0) {
                        cursor = cursor.limit(limit);
                    } else {
                        // Optional: Send an error if limit is invalid, or just ignore it
                        return res.status(400).send({ message: "Invalid 'limit' parameter. Must be a positive number." });
                    }
                }

                // Execute the query and convert to array
                const blogs = await cursor.toArray();
                res.send(blogs);

            } catch (error) {
                console.error("Error fetching blogs:", error); // Log the actual error for debugging
                res.status(500).send({ message: "Internal Server Error" });
            }
        });

        app.get('/blogs/:id', async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) }
            const result = await blogsCollection.findOne(filter);
            res.send(result)
        })
        // 2. GET /blogs/author/:email - Fetch blogs by author's email (for agent)
        app.get('/blogs/author/:email', async (req, res) => {
            try {
                const authorEmail = req.params.email;
                const query = { authorEmail: authorEmail };
                const blogs = await blogsCollection.find(query).toArray();
                res.send(blogs);
            } catch (error) {
                // console.error("Error fetching blogs by author email:", error);
                res.status(500).send({ message: "Internal Server Error" });
            }
        });

        // 3. POST /blogs - Create a new blog post
        app.post('/blogs', async (req, res) => {
            try {
                const blogData = req.body;
                // Ensure required fields are present
                if (!blogData.title || !blogData.content || !blogData.authorEmail || !blogData.authorName) {
                    return res.status(400).send({ message: "Missing required blog data (title, content, authorEmail, authorName)." });
                }
                // Set initial publish date if not provided (though frontend sets it)
                if (!blogData.publishDate) {
                    blogData.publishDate = new Date().toISOString();
                }
                blogData.lastUpdatedAt = new Date().toISOString(); // Set last updated date

                const result = await blogsCollection.insertOne(blogData);
                res.status(201).send({
                    message: "Blog post created successfully!",
                    insertedId: result.insertedId,
                });
            } catch (error) {
                // console.error("Error creating blog post:", error);
                res.status(500).send({ message: "Internal Server Error" });
            }
        });

        // 4. PATCH /blogs/:id - Update an existing blog post
        app.patch('/blogs/:id', verifyToken, async (req, res) => {
            try {
                const id = req.params.id;
                const updates = req.body;

                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: "Invalid Blog ID format." });
                }

                const filter = { _id: new ObjectId(id) };
                const updateDoc = {
                    $set: {
                        title: updates.title,
                        content: updates.content,
                        // authorName and authorEmail should generally not be changed on update
                        // publishDate should remain the original publish date
                        lastUpdatedAt: new Date().toISOString(), // Update last updated timestamp
                    },
                };
                const result = await blogsCollection.updateOne(filter, updateDoc);

                if (result.matchedCount === 0) {
                    return res.status(404).send({ message: "Blog not found." });
                }
                res.send({ message: "Blog updated successfully!", modifiedCount: result.modifiedCount });
            } catch (error) {
                // console.error("Error updating blog post:", error);
                res.status(500).send({ message: "Internal Server Error" });
            }
        });
        app.patch('/blogs/:id/visit', async (req, res) => {
            try {
                const id = req.params.id;

                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: "Invalid Blog ID format." });
                }

                const filter = { _id: new ObjectId(id) };
                const updateDoc = {
                    $inc: { visitCount: 1 }, // Increment visitCount by 1
                };
                const options = { upsert: false }; // Do not create if not found

                const result = await blogsCollection.updateOne(filter, updateDoc, options);

                if (result.matchedCount === 0) {
                    return res.status(404).send({ message: "Blog not found." });
                }
                res.send({ message: "Visit count updated successfully!", modifiedCount: result.modifiedCount });
            } catch (error) {
                // console.error("Error updating blog visit count:", error);
                res.status(500).send({ message: "Internal Server Error" });
            }
        });
        // 5. DELETE /blogs/:id - Delete a blog post
        app.delete('/blogs/:id', verifyToken, async (req, res) => {
            try {
                const id = req.params.id;

                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: "Invalid Blog ID format." });
                }

                const filter = { _id: new ObjectId(id) };
                const result = await blogsCollection.deleteOne(filter);

                if (result.deletedCount === 0) {
                    return res.status(404).send({ message: "Blog not found." });
                }
                res.send({ message: "Blog deleted successfully!", deletedCount: result.deletedCount });
            } catch (error) {
                // console.error("Error deleting blog post:", error);
                res.status(500).send({ message: "Internal Server Error" });
            }
        });



        app.post('/applications', verifyToken, async (req, res) => {
            const applicationData = req.body
            applicationData.status = 'Pending'
            // console.log(applicationData);

            const result = await applicationsCollection.insertOne(applicationData)
            res.send(result)
        })
        app.get('/applications', async (req, res) => {
            const result = await applicationsCollection.find().toArray()
            res.send(result)
        })
        // app.patch('/applicationUpdate/:id', async (req, res) => {
        //     const id = req.params.id;
        //     const updates = req.body
        //     // console.log(updates);
        //     const updateDoc = {

        //         $set: {
        //             // status: updates?.status,
        //             paymentStatus: 'Due'
        //         }

        //     }
        //     const filter = { _id: new ObjectId(id) }

        //     const result = await applicationsCollection.updateOne(filter, updateDoc)
        //     res.send(result)

        // })
        // MODIFIED: /applicationUpdate/:id to handle paymentStatus AND agentId
        // app.patch('/applicationUpdate/:id', async (req, res) => {
        //     const id = req.params.id;
        //     const { status, paymentStatus, agentId } = req.body; // Now accepts agentId
        //     const filter = { _id: new ObjectId(id) };
        //     const updateDoc = { $set: {} };

        //     if (status) {
        //         updateDoc.$set.status = status;
        //     }
        //     if (paymentStatus) { // Handle paymentStatus update
        //         updateDoc.$set.paymentStatus = paymentStatus;
        //     }
        //     if (agentId) { // NEW: Handle agentId update
        //         updateDoc.$set.agentId = agentId;
        //     }

        //     const result = await applicationsCollection.updateOne(filter, updateDoc);
        //     res.send(result);
        // });


        app.patch('/applicationUpdate/:id', verifyToken, async (req, res) => {
            const id = req.params.id;
            const { status, paymentStatus, agentId, rejectFeedback } = req.body; // Added rejectFeedback
            const filter = { _id: new ObjectId(id) };
            const updateDoc = { $set: {} };

            if (status) {
                updateDoc.$set.status = status;
            }
            if (paymentStatus) {
                updateDoc.$set.paymentStatus = 'Due';
            }
            if (agentId) {
                updateDoc.$set.agentId = agentId;
            }
            if (rejectFeedback) { // NEW: Handle rejectFeedback update
                updateDoc.$set.rejectFeedback = rejectFeedback;
            }

            try {
                const result = await applicationsCollection.updateOne(filter, updateDoc);
                if (result.matchedCount === 0) {
                    return res.status(404).send({ message: 'Application not found' });
                }
                res.send(result);
            } catch (error) {
                // console.error('Error updating application:', error.message);
                res.status(500).send({ message: 'Failed to update application', error: error.message });
            }
        });



        app.post('/dataForAgents', verifyToken, async (req, res) => {
            const agentAssignmentData = req.body;
            // console.log(agentAssignmentData);
            const result = await dataForAgentsCollection.insertOne(agentAssignmentData)
            res.send(result)
        })

        app.get('/all-data-that-are-approvedByAgent/:email', async (req, res) => {
            const email = req.params.email
            const result = await dataForAgentsCollection.find({ customerEmail: email }).toArray();
            res.send(result)

        })
        app.get('/get-all-data-for-agents/:email', verifyToken, async (req, res) => {
            const email = req.params.email;

            try {
                // Step 1: Find all applications where agentEmail === email from params
                const assignedData = await dataForAgentsCollection
                    .find({ agentEmail: email })
                    .toArray();

                // Step 2: Send only matching assigned applications
                res.send(assignedData);

            } catch (error) {
                // console.error('Error fetching agent-assigned data:', error.message);
                res.status(500).send({ message: 'Server error while fetching assigned data' });
            }
        });


        //
        app.post('/create-payment-intent', verifyToken, async (req, res) => {
            const { amount } = req.body;
            const calculatedAmountInCents = Math.round(amount * 100); // Stripe expects amount in cents

            try {
                const paymentIntent = await stripe.paymentIntents.create({
                    amount: calculatedAmountInCents,
                    currency: 'bdt', // Or your desired currency (e.g., 'usd')
                    payment_method_types: ['card'],
                });
                res.send({ clientSecret: paymentIntent.client_secret });
            } catch (error) {
                // console.error("Error creating Payment Intent:", error);
                res.status(500).send({ error: error.message });
            }
        });


        app.patch('/dataForAgents/:id', verifyToken, async (req, res) => {
            const { id } = req.params;
            const { status, policyId } = req.body;

            try {
                // 1. Update the status in dataForAgents collection
                const filter = { _id: new ObjectId(id) };
                const updateDoc = {
                    $set: {
                        status: status,
                        paymentStatus: 'Due',
                    },
                };

                const updateResult = await dataForAgentsCollection.updateOne(filter, updateDoc);

                if (updateResult.modifiedCount === 0) {
                    return res.status(404).send({ success: false, message: 'No document updated or not found.' });
                }

                // 2. If approved, increment purchaseCount in policies collection
                if (status === 'Approved' && policyId) {
                    await policiesCollection.updateOne(
                        { _id: new ObjectId(policyId) },
                        {
                            $inc: { purchaseCount: 1 },
                        }
                    );
                }

                res.send({ success: true, message: 'Status updated and policy count incremented if applicable.' });

            } catch (error) {
                // console.error('Error in patching /dataForAgents:', error.message);
                res.status(500).send({ success: false, message: 'Internal server error.' });
            }
        });



















        //forpaymets
        app.get('/applications/:id', async (req, res) => {
            const id = req.params.id;
            try {
                // Ensure the ID from the URL parameter is converted to a MongoDB ObjectId
                // This is crucial for querying documents by their _id field.
                const application = await applicationsCollection.findOne({ _id: new ObjectId(id) });

                if (!application) {
                    // If no application is found with the given ID, send a 404 Not Found response.
                    return res.status(404).send({ message: 'Application not found' });
                }

                // If found, send the full application document.
                res.send(application);
            } catch (error) {
                // Handle potential errors, e.g., if the provided ID is not a valid ObjectId format.
                // console.error('Error fetching single application by ID:', error);
                // Sending a 400 Bad Request for invalid ID format, or 500 for other server errors.
                if (error.name === 'BSONTypeError') { // Specific error for invalid ObjectId format
                    return res.status(400).send({ message: 'Invalid application ID format' });
                }
                res.status(500).send({ message: 'Server error fetching application', error: error.message });
            }
        });
        app.get('/applications/:email/approved-for-payment', verifyToken, async (req, res) => {
            try {
                const userEmail = req?.params?.email;
                // This is the line (index.js:178:50) that might be problematic if req.user is undefined.
                // The `?.` (optional chaining) prevents a crash but doesn't solve if req.user is truly empty.
                const authenticatedUserEmail = req?.user?.email;

                // console.log("Route Handler: Param Email from URL:", userEmail);
                // console.log("Route Handler: Authenticated Email (from req.user):", authenticatedUserEmail);
                // console.log("Route Handler: Full req.user object content:", req.user); // ⭐ CRITICAL DEBUG LOG ⭐

                // Enhanced check: If req.user is missing (e.g., middleware failed) or email mismatch
                if (!req.user || userEmail !== authenticatedUserEmail) {
                    // console.log("Route Handler: Forbidden - req.user is missing or email does not match URL parameter.");
                    return res.status(403).send({ message: 'Forbidden: Unauthorized access or email mismatch.' });
                }

                // If execution reaches here, req.user should be populated, and emails should match.
                // Query: Find applications where 'personal.email' matches and 'status' is 'Approved'.
                const query = {
                    'personal.email': userEmail,
                    'status': 'Approved'
                };
                const result = await applicationsCollection.find(query).toArray();
                res.status(200).send(result);
            } catch (error) {
                // console.error("Route Handler: Error fetching approved applications:", error);
                res.status(500).send({ message: "Failed to fetch approved applications for payment.", error: error.message });
            }
        });





        app.get('/applications/user/:email', async (req, res) => {
            // console.log("--- Hitting /applications/user/:email route ---"); // See if this gets hit
            const email = req.params.email;
            // console.log("Requesting apps for email:", email);

            try {
                const result = await applicationsCollection.find({ "personal.email": email }).toArray();

                if (result.length > 0) {
                    res.send(result);
                } else {
                    res.status(404).send({ message: "No applications found for this email." });
                }
            } catch (error) {
                // console.error("Error fetching applications (all):", error);
                res.status(500).send({ message: "Internal server error." });
            }
        });




        app.post('/reviews', verifyToken, async (req, res) => {
            try {
                const reviewData = req.body;

                // Basic validation
                if (!reviewData.userEmail || !reviewData.policyId || !reviewData.rating || !reviewData.feedback) {
                    return res.status(400).send({ message: "Missing required review fields." });
                }

                const result = await reviewsCollection.insertOne(reviewData);
                res.status(201).send({
                    message: "Review submitted successfully!",
                    insertedId: result.insertedId,
                    acknowledged: result.acknowledged
                });
            } catch (error) {
                // console.error("Error submitting review:", error);
                res.status(500).send({ message: "Failed to submit review.", error: error.message });
            }
        });

        app.get('/reviews', async (req, res) => {
            const result = await reviewsCollection.find().toArray();
            res.send(result)
        })
        // routes/applications.js or inside your main Express file
        // Assuming 'applicationsCollection' is your MongoDB collection object


        app.post('/subscribe-newsletter', verifyToken, async (req, res) => {
            const { email } = req.body;
            const query = { email }
            const result = await newsletterSubscribersCollection.insertOne(query)
            res.send(result)
        });



        app.post('/user', verifyToken, async (req, res) => {

            const userData = req.body
            userData.role = 'customer'
            const now = new Date().toISOString()
            userData.created_at = now;
            userData.last_loggedIn = now;
            const query = { email: userData?.email }
            const alreadyExist = await usersCollection.findOne(query)
            if (alreadyExist) {
                const result = await usersCollection.updateOne(query, {
                    $set: {
                        last_loggedIn: now
                    }
                })
                return res.send(result)
            }

            const result = await usersCollection.insertOne(userData)
            res.send(result)
        })
        app.get('/users', verifyToken, async (req, res) => {
            // console.log(req?.user);
            const filter = {
                email: {
                    $ne: req?.user?.email
                }
            }
            const result = await usersCollection.find(filter).toArray()
            res.send(result)
        })

        // get a user's role
        app.get('/user/role/:email', async (req, res) => {
            const email = req.params.email
            const result = await usersCollection.findOne({ email })
            if (!result) return res.status(404).send({ message: 'User Not Found.' })
            res.send({ role: result?.role })
        })
        //

        app.patch(
            '/user/role/update/:email', verifyToken, async (req, res) => {
                const email = req.params.email;


                const { role } = req.body;
                // console.log(email, role);

                const filter = { email };
                const updateDoc = {
                    $set: {
                        role: role
                    },
                };

                const result = await usersCollection.updateOne(filter, updateDoc);
                // console.log(result);

                res.send(result);
            }
        );


        app.get('/agents', async (req, res) => {
            try {
                const agents = await usersCollection.find({ role: 'agent' }).toArray();

                if (!agents.length) {
                    return res.status(404).send({ message: 'No agents found' });
                }

                res.send(agents); // Return all users where role === 'agent'
            } catch (error) {
                // console.error('Error fetching agents:', error);
                res.status(500).send({ message: 'Internal Server Error' });
            }
        });

        // Send a ping to confirm a successful connection
        // await client.db('admin').command({ ping: 1 })
        // console.log(
        //     'Pinged your deployment. You successfully connected to MongoDB!'
        // )
    } finally {
        // Ensures that the client will close when you finish/error
    }
}
run().catch(console.dir)


app.get('/', (req, res) => {
    res.send(`
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>System Interface</title>
    <style>
      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
      }

      html, body {
        height: 100%;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        overflow: hidden;
      }

      video.bg-video {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        object-fit: cover;
        z-index: -1;
      }

      .content {
        position: relative;
        z-index: 1;
        height: 100%;
        width: 100%;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        text-align: center;
        color: #ffffff;
        text-shadow: 0 0 8px #00ffff, 0 0 15px #00ffff;
        padding: 20px;
        animation: fadeIn 1.5s ease-out forwards;
      }

      h1 {
        font-size: 2.8em;
        margin-bottom: 16px;
        font-weight: 600;
        letter-spacing: 1px;
        animation: slideIn 2s ease forwards;
      }

      p {
        font-size: 1.1em;
        max-width: 700px;
        line-height: 1.6;
        opacity: 0.85;
        animation: fadeInText 3s ease forwards;
      }

      .features {
        margin-top: 40px;
        font-size: 20px;
        opacity: 1;
        text-shadow: none;
        color: #AAFF00;
        font-family: monospace;
        line-height: 1.5;
        animation: fadeInText 4s ease forwards;
      }

      @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
      }

      @keyframes slideIn {
        from { opacity: 0; transform: translateY(30px); }
        to { opacity: 1; transform: translateY(0); }
      }

      @keyframes fadeInText {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 0.9; transform: translateY(0); }
      }
    </style>
  </head>
  <body>
    <video class="bg-video" autoplay muted loop playsinline>
      <source src="https://r2.guns.lol/ee63caf9-7001-4509-b0a2-b1fbee1c043c.mp4" type="video/mp4">
      Your browser does not support the video tag.
    </video>

    <div class="content">
      <h1>Welcome to RibaCharo Interface</h1>
     
      <div class="features">
       ▸ MongoDB database connected and operational<br>
       ▸ JWT-based secure authentication enabled<br>
       ▸ CORS policy configured for cross-origin access<br>
       ▸ Express.js server running smoothly<br>
       ▸ Scalable and maintainable backend architecture<br>

      </div>
    </div>
  </body>
  </html>
  `);
});



app.listen(port, () => {
    console.log(`Riba Charo is running on por ${port}`)
})




      app.post("/Application", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).send({ message: "Email is required" });
    }

    //  Removed duplicate email check
    const result = await Application.insertOne(req.body);
    res.send({ insertedId: result.insertedId });
  } catch (error) {
    console.error("Error inserting application:", error);
    res.status(500).send({ message: "Internal server error" });
  }
});

app.get("/Application", async (req, res) => {
  try {
    const email = req.query.email;
    if (!email) return res.status(400).send({ message: "Email is required" });

    const applications = await Application.find({ email }).toArray();
    res.send(applications);
  } catch (error) {
    console.error("Fetch error:", error);
    res.status(500).send({ message: "Server error" });
  }
});

app.delete("/Application/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const result = await Application.deleteOne({ _id: new ObjectId(id) });
    res.send(result);
  } catch (error) {
    console.error("Delete error:", error);
    res.status(500).send({ message: "Server error" });
  }
});


// amotun st
app.post("/SendParcel", async (req, res) => {
  try {
    const data = req.body;
    
    
    const applicationData = {
      ...data,
      applicationId: `APP-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      submissionDate: new Date().toISOString(),
      creation_date: new Date().toISOString(),
    };
    const result = await amounts.insertOne(applicationData);
    
    if (result.insertedId) {
      res.send({ 
        insertedId: result.insertedId,
        message: "Application submitted successfully",
        applicationId: applicationData.applicationId
      });
    } else {
      res.status(500).send({ message: "Failed to submit application" });
    }
    
  } catch (error) {
    console.error("Error inserting application:", error);
    res.status(500).send({ 
      message: "Internal server error", 
      error: error.message 
    });
  }
});
// get 
// GET route to fetch parcels by email
app.get("/SendParcel", async (req, res) => {
  const email = req.query.email;
  const result = await amounts.find({ email }).toArray();
  res.send(result);
});
// delet 
app.delete("/SendParcel/:id", async (req, res) => {
  const id = req.params.id;
  const result = await amounts.deleteOne({ _id: new ObjectId(id) });
  res.send(result);
});

// prement  
app.get("/SendParcel/:id", async (req, res) => {
  try {
    const id = req.params.id;
    
    // Validate ObjectId format
    if (!ObjectId.isValid(id)) {
      return res.status(400).send({ message: "Invalid parcel ID format" });
    }
    
    const parcel = await amounts.findOne({ _id: new ObjectId(id) });
    
    if (!parcel) {
      return res.status(404).send({ message: "Parcel not found" });
    }
    
    res.send(parcel);
  } catch (error) {
    console.error("Error fetching parcel:", error);
    res.status(500).send({ message: "Server error", error: error.message });
  }
});


// amotun end

        // my postede end 

        app.get("/users/search", async (req, res) => {
            const emailQuery = req.query.email;
            if (!emailQuery) {
                return res.status(400).send({ message: "Missing email query" });
            }

            const regex = new RegExp(emailQuery, "i"); // case-insensitive partial match

            try {
                const users = await usersCollection
                    .find({ email: { $regex: regex } })
                    // .project({ email: 1, createdAt: 1, role: 1 })
                    .limit(10)
                    .toArray();
                res.send(users);
            } catch (error) {
                console.error("Error searching users", error);
                res.status(500).send({ message: "Error searching users" });
            }
        });

        // GET: Get user role by email
        app.get('/users/:email/role', async (req, res) => {
            try {
                const email = req.params.email;

                if (!email) {
                    return res.status(400).send({ message: 'Email is required' });
                }

                const user = await usersCollection.findOne({ email });

                if (!user) {
                    return res.status(404).send({ message: 'User not found' });
                }

                res.send({ role: user.role || 'user' });
                console.log(user);
            } catch (error) {
                console.error('Error getting user role:', error);
                res.status(500).send({ message: 'Failed to get role' });
            }
        });


        app.post('/users', async (req, res) => {
            const email = req.body.email;
            const userExists = await usersCollection.findOne({ email })
            if (userExists) {
                // update last log in
                return res.status(200).send({ message: 'User already exists', inserted: false });
            }
            const user = req.body;
            const result = await usersCollection.insertOne(user);
            res.send(result);
        })

        app.patch("/users/:id/role", verifyFBToken, verifyAdmin, async (req, res) => {
            const { id } = req.params;
            const { role } = req.body;

            if (!["admin", "user"].includes(role)) {
                return res.status(400).send({ message: "Invalid role" });
            }

            try {
                const result = await usersCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { role } }
                );
                res.send({ message: `User role updated to ${role}`, result });
            } catch (error) {
                console.error("Error updating user role", error);
                res.status(500).send({ message: "Failed to update user role" });
            }
        });


        // parcels api
        // GET: All parcels OR parcels by user (created_by), sorted by latest
        app.get('/parcels', verifyFBToken, async (req, res) => {
            try {
                const { email, payment_status, delivery_status } = req.query;
                let query = {}
                if (email) {
                    query = { created_by: email }

                }

                if (payment_status) {
                    query.payment_status = payment_status
                }

                if (delivery_status) {
                    query.delivery_status = delivery_status
                }

                const options = {
                    sort: { createdAt: -1 }, // Newest first
                };

                console.log('parcel query', req.query, query)

                const parcels = await parcelsCollection.find(query, options).toArray();
                res.send(parcels);
            } catch (error) {
                console.error('Error fetching parcels:', error);
                res.status(500).send({ message: 'Failed to get parcels' });
            }
        });

        // GET: Get a specific parcel by ID
        app.get('/parcels/:id', async (req, res) => {

            try {
                const id = req.params.id;

                const parcel = await parcelsCollection.findOne({ _id: new ObjectId(id) });

                if (!parcel) {
                    return res.status(404).send({ message: 'Parcel not found' });
                }

                res.send(parcel);
            } catch (error) {
                console.error('Error fetching parcel:', error);
                res.status(500).send({ message: 'Failed to fetch parcel' });
            }

        });

        app.get('/parcels/delivery/status-count', async (req, res) => {
            const pipeline = [
                {
                    $group: {
                        _id: '$delivery_status',
                        count: {
                            $sum: 1
                        }
                    }
                },
                {
                    $project: {
                        status: '$_id',
                        count: 1,
                        _id: 0
                    }
                }
            ];

            const result = await parcelsCollection.aggregate(pipeline).toArray();
            res.send(result);
        })

        // GET: Get pending delivery tasks for a rider
        app.get('/rider/parcels', verifyFBToken, verifyRider, async (req, res) => {
            try {
                const email = req.query.email;

                if (!email) {
                    return res.status(400).send({ message: 'Rider email is required' });
                }

                const query = {
                    assigned_rider_email: email,
                    delivery_status: { $in: ['rider_assigned', 'in_transit'] },
                };

                const options = {
                    sort: { creation_date: -1 }, // Newest first
                };

                const parcels = await parcelsCollection.find(query, options).toArray();
                res.send(parcels);
            } catch (error) {
                console.error('Error fetching rider tasks:', error);
                res.status(500).send({ message: 'Failed to get rider tasks' });
            }
        });

        // GET: Load completed parcel deliveries for a rider
        app.get('/rider/completed-parcels', verifyFBToken, verifyRider, async (req, res) => {
            try {
                const email = req.query.email;

                if (!email) {
                    return res.status(400).send({ message: 'Rider email is required' });
                }

                const query = {
                    assigned_rider_email: email,
                    delivery_status: {
                        $in: ['delivered', 'service_center_delivered']
                    },
                };

                const options = {
                    sort: { creation_date: -1 }, // Latest first
                };

                const completedParcels = await parcelsCollection.find(query, options).toArray();

                res.send(completedParcels);

            } catch (error) {
                console.error('Error loading completed parcels:', error);
                res.status(500).send({ message: 'Failed to load completed deliveries' });
            }
        });



        // POST: Create a new parcel
        app.post('/parcels', async (req, res) => {
            try {
                const newParcel = req.body;
                // newParcel.createdAt = new Date();
                const result = await parcelsCollection.insertOne(newParcel);
                res.status(201).send(result);
            } catch (error) {
                console.error('Error inserting parcel:', error);
                res.status(500).send({ message: 'Failed to create parcel' });
            }
        });

        app.patch("/parcels/:id/assign", async (req, res) => {
            const parcelId = req.params.id;
            const { riderId, riderName, riderEmail } = req.body;

            try {
                // Update parcel
                await parcelsCollection.updateOne(
                    { _id: new ObjectId(parcelId) },
                    {
                        $set: {
                            delivery_status: "rider_assigned",
                            assigned_rider_id: riderId,
                            assigned_rider_email: riderEmail,
                            assigned_rider_name: riderName,
                        },
                    }
                );

                // Update rider
                await ridersCollection.updateOne(
                    { _id: new ObjectId(riderId) },
                    {
                        $set: {
                            work_status: "in_delivery",
                        },
                    }
                );

                res.send({ message: "Rider assigned" });
            } catch (err) {
                console.error(err);
                res.status(500).send({ message: "Failed to assign rider" });
            }
        });

        app.patch("/parcels/:id/status", async (req, res) => {
            const parcelId = req.params.id;
            const { status } = req.body;
            const updatedDoc = {
                delivery_status: status
            }

            if (status === 'in_transit') {
                updatedDoc.picked_at = new Date().toISOString()
            }
            else if (status === 'delivered') {
                updatedDoc.delivered_at = new Date().toISOString()
            }

            try {
                const result = await parcelsCollection.updateOne(
                    { _id: new ObjectId(parcelId) },
                    {
                        $set: updatedDoc
                    }
                );
                res.send(result);
            } catch (error) {
                res.status(500).send({ message: "Failed to update status" });
            }
        });


    // agent st 
   app.post("/agent-requests", async (req, res) => {
  try {
    const data = {
      ...req.body,
      status: "pending"
    };
    const result = await agentRequestsCollection.insertOne(data);
    if (result.insertedId) {
      res.status(201).json({ insertedId: result.insertedId });
    } else {
      res.status(500).json({ error: "Failed to submit request" });
    }
  } catch (error) {
    console.error("POST /agent-requests error:", error);
    res.status(500).json({ error: "Failed to submit request" });
  }
});


app.get("/agent-requests", async (req, res) => {
  try {
    const requests = await AgentRequest.find();
    res.json(requests);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch requests" });
  }
});

app.patch("/agent-requests/:id/approve", async (req, res) => {
  try {
    const request = await AgentRequest.findByIdAndUpdate(req.params.id, { status: "approved" });
    if (request) {
      await User.findOneAndUpdate({ email: request.email }, { role: "agent" });
      res.json({ message: "Agent approved" });
    } else {
      res.status(404).json({ message: "Request not found" });
    }
  } catch (error) {
    res.status(500).json({ error: "Approval failed" });
  }
});

app.patch("/agent-requests/:id/reject", async (req, res) => {
  try {
    await AgentRequest.findByIdAndUpdate(req.params.id, { status: "rejected" });
    res.json({ message: "Agent rejected" });
  } catch (error) {
    res.status(500).json({ error: "Rejection failed" });
  }
});
// agent end


//  existing route: keep this unchanged
app.patch("/parcels/:id/status", async (req, res) => {
  const parcelId = req.params.id;
  const { status } = req.body;
  const updatedDoc = {
    delivery_status: status
  };

  if (status === 'in_transit') {
    updatedDoc.picked_at = new Date().toISOString();
  } else if (status === 'delivered') {
    updatedDoc.delivered_at = new Date().toISOString();
  }

  try {
    const result = await parcelsCollection.updateOne(
      { _id: new ObjectId(parcelId) },
      { $set: updatedDoc }
    );
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to update status" });
  }
});


    // agent end 
       
app.get("/addadmin/popular", async (req, res) => {
  try {
    // Step 1: Count each successful payment individually
    const paymentCounts = await paymentsCollection.aggregate([
      {
        $match: {
          status: "completed" // Only completed payments count
        }
      },
      {
        $lookup: {
          from: "SendParcel",
          localField: "parcelId",
          foreignField: "_id",
          as: "applicationData"
        }
      },
      {
        $unwind: "$applicationData"
      },
      {
        $match: {
          "applicationData.policyId": { $exists: true, $ne: null }
        }
      },
      {
        $group: {
          _id: "$applicationData.policyId", // Group by policy ID
          paymentCount: { $sum: 1 }, // Each payment adds +1 to counter
          totalRevenue: { $sum: "$amount" },
          lastPaymentDate: { $max: "$paymentDate" }
        }
      },
      {
        $sort: { paymentCount: -1 } // Sort by highest payment count
      },
      {
        $limit: 6 // Top 6 most paid policies
      }
    ]).toArray();

    console.log("Payment counts for policies:", paymentCounts);

    // Step 2: Get policy details and add payment counts
    let topPolicies = [];
    
    if (paymentCounts.length > 0) {
      const policyIds = paymentCounts.map(count => {
        try {
          return new ObjectId(count._id);
        } catch (error) {
          console.log("Invalid ObjectId:", count._id);
          return null;
        }
      }).filter(id => id !== null);
      
      if (policyIds.length > 0) {
        topPolicies = await addadmins.find({
          _id: { $in: policyIds }
        }).toArray();
        
        // Add payment counting to each policy
        topPolicies = topPolicies.map(policy => {
          const paymentData = paymentCounts.find(count => 
            count._id?.toString() === policy._id.toString()
          );
          
          return {
            ...policy,
            paymentCount: paymentData ? paymentData.paymentCount : 0,
            salesCount: paymentData ? paymentData.paymentCount : 0, // Alias for frontend
            totalRevenue: paymentData ? paymentData.totalRevenue : 0,
            lastSale: paymentData ? paymentData.lastPaymentDate : null
          };
        });
        
        // Sort by payment count (descending)
        topPolicies.sort((a, b) => b.paymentCount - a.paymentCount);
      }
    }
    
    // Fill remaining slots with latest policies (if needed)
    if (topPolicies.length < 6) {
      const remainingCount = 6 - topPolicies.length;
      const usedIds = topPolicies.map(p => p._id);
      
      const additionalPolicies = await addadmins.find({
        _id: { $nin: usedIds }
      })
      .sort({ createdAt: -1 })
      .limit(remainingCount)
      .toArray();
      
      // Add zero counts to additional policies
      const additionalWithCount = additionalPolicies.map(policy => ({
        ...policy,
        paymentCount: 0,
        salesCount: 0,
        totalRevenue: 0,
        lastSale: null
      }));
      
      topPolicies = [...topPolicies, ...additionalWithCount];
    }
    
    console.log(`Returning ${topPolicies.length} popular policies with payment counts`);
    res.send(topPolicies);
    
  } catch (error) {
    console.error("Error fetching popular policies:", error);
    res.status(500).send({ 
      message: "Failed to fetch popular policies", 
      error: error.message 
    });
  }
});

app.get("/addadmin_popular", async (req, res) => {
  try {
    const category = req.query.category;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 9; // 9 per page
    const skip = (page - 1) * limit;

    const query = {};

    if (category && category !== "All") {
      query.category = category;
    }

    const total = await addadmins.countDocuments(query);
    const policies = await addadmins
      .find(query)
      .skip(skip)
      .limit(limit)
      .toArray();

    res.send({
      policies,
      total,
    });
  } catch (error) {
    res.status(500).send({ message: "Server error", error});
}
});
// All policies with individual payment counts
app.get("/addadmin", async (req, res) => {
  try {
    const allPolicies = await addadmins.find({})
      .sort({ createdAt: -1 })
      .toArray();
    
    // Add payment count to each policy individually
    const policiesWithCounts = await Promise.all(
      allPolicies.map(async (policy) => {
        // Count completed payments for this specific policy
        const paymentCount = await paymentsCollection.aggregate([
          {
            $match: { status: "completed" }
          },
          {
            $lookup: {
              from: "SendParcel",
              localField: "parcelId",
              foreignField: "_id",
              as: "applicationData"
            }
          },
          {
            $unwind: "$applicationData"
          },
          {
            $match: {
              "applicationData.policyId": policy._id.toString()
            }
          },
          {
            $count: "totalPayments"
          }
        ]).toArray();
        
        const count = paymentCount.length > 0 ? paymentCount[0].totalPayments : 0;
        
        // Get total revenue for this policy
        const revenueData = await paymentsCollection.aggregate([
          {
            $match: { status: "completed" }
          },
          {
            $lookup: {
              from: "SendParcel",
              localField: "parcelId",
              foreignField: "_id",
              as: "applicationData"
            }
          },
          {
            $unwind: "$applicationData"
          },
          {
            $match: {
              "applicationData.policyId": policy._id.toString()
            }
          },
          {
            $group: {
              _id: null,
              totalRevenue: { $sum: "$amount" }
            }
          }
        ]).toArray();
        
        const revenue = revenueData.length > 0 ? revenueData[0].totalRevenue : 0;
        
        return {
          ...policy,
          paymentCount: count,
          salesCount: count,
          totalRevenue: revenue,
          applicationCount: count // Keep for compatibility
        };
      })
    );
    
    console.log(`Returning ${policiesWithCounts.length} policies with payment counts`);
    res.send(policiesWithCounts);
    
  } catch (error) {
    console.error("Error fetching all policies:", error);
    res.status(500).send({ 
      message: "Failed to fetch all policies", 
      error: error.message 
    });
  }
});

// Updated payment recording - increments count by 1 for each payment
app.post('/payments', async (req, res) => {
    try {
        const { parcelId, email, amount, transactionId, paymentMethod } = req.body;
        
        console.log('Recording payment for counting increment:', { parcelId, email, amount, transactionId });
        
        // Step 1: Record payment in payments collection
        const paymentData = {
            parcelId: new ObjectId(parcelId),
            email,
            amount: parseFloat(amount),
            transactionId,
            paymentMethod,
            paymentDate: new Date(),
            status: 'completed', // Mark as completed for counting
            createdAt: new Date()
        };
        
        const paymentResult = await paymentsCollection.insertOne(paymentData);
        
        // Step 2: Update parcel payment status
        const updateResult = await amounts.updateOne(
            { _id: new ObjectId(parcelId) },
            { 
                $set: { 
                    payment_status: 'paid',
                    transactionId: transactionId,
                    paymentDate: new Date(),
                    paidAt: new Date()
                }
            }
        );
        
        // Step 3: Get policy info for logging
        const parcelInfo = await amounts.findOne({ _id: new ObjectId(parcelId) });
        
        if (parcelInfo && parcelInfo.policyId) {
            console.log(`Payment counted for policy ${parcelInfo.policyId}. New payment recorded.`);
            
            // Optional: Get updated count for this policy
            const updatedCount = await paymentsCollection.aggregate([
                {
                    $match: { status: "completed" }
                },
                {
                    $lookup: {
                        from: "SendParcel",
                        localField: "parcelId",
                        foreignField: "_id",
                        as: "applicationData"
                    }
                },
                {
                    $unwind: "$applicationData"
                },
                {
                    $match: {
                        "applicationData.policyId": parcelInfo.policyId
                    }
                },
                {
                    $count: "totalPayments"
                }
            ]).toArray();
            
            const newCount = updatedCount.length > 0 ? updatedCount[0].totalPayments : 1;
            console.log(`Policy ${parcelInfo.policyId} now has ${newCount} payments`);
        }
        
        console.log('Payment recorded and counting updated:', { paymentResult, updateResult });
        
        if (paymentResult.insertedId && updateResult.modifiedCount > 0) {
            res.send({ 
                insertedId: paymentResult.insertedId,
                message: 'Payment recorded and count incremented successfully',
                parcelUpdated: true
            });
        } else {
            res.status(400).send({ message: 'Failed to record payment or update parcel' });
        }
        
    } catch (error) {
        console.error('Payment recording error:', error);
        res.status(500).send({
            message: 'Payment recording failed',
            error: error.message
        });
    }
});

// Get real-time payment count for a specific policy
app.get("/addadmin/:id/payment-count", async (req, res) => {
  try {
    const policyId = req.params.id;
    
    // Count completed payments for this policy
    const paymentStats = await paymentsCollection.aggregate([
      {
        $match: { status: "completed" }
      },
      {
        $lookup: {
          from: "SendParcel",
          localField: "parcelId",
          foreignField: "_id",
          as: "applicationData"
        }
      },
      {
        $unwind: "$applicationData"
      },
      {
        $match: {
          "applicationData.policyId": policyId
        }
      },
      {
        $group: {
          _id: null,
          paymentCount: { $sum: 1 },
          totalRevenue: { $sum: "$amount" },
          avgAmount: { $avg: "$amount" },
          lastPayment: { $max: "$paymentDate" }
        }
      }
    ]).toArray();
    
    const stats = paymentStats.length > 0 ? paymentStats[0] : {
      paymentCount: 0,
      totalRevenue: 0,
      avgAmount: 0,
      lastPayment: null
    };
    
    res.send({
      policyId,
      currentCount: stats.paymentCount,
      totalRevenue: stats.totalRevenue,
      averageAmount: stats.avgAmount,
      lastPaymentDate: stats.lastPayment
    });
    
  } catch (error) {
    console.error("Error fetching payment count:", error);
    res.status(500).send({ 
      message: "Failed to fetch payment count", 
      error: error.message 
    });
  }
});

// Update SendParcel to properly link policy ID
app.post("/SendParcel", async (req, res) => {
  try {
    const data = req.body;
    
    const applicationData = {
      ...data,
      applicationId: `APP-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      submissionDate: new Date().toISOString(),
      creation_date: new Date().toISOString(),
      // Ensure policy ID is properly stored for counting
      policyId: data.policyId || data.selectedPolicyId || null,
      paymentStatus: 'pending' // Initial status
    };
    
    const result = await amounts.insertOne(applicationData);
    
    if (result.insertedId) {
      res.send({ 
        insertedId: result.insertedId,
        message: "Application submitted successfully",
        applicationId: applicationData.applicationId
      });
    } else {
      res.status(500).send({ message: "Failed to submit application" });
    }
    
  } catch (error) {
    console.error("Error inserting application:", error);
    res.status(500).send({ 
      message: "Internal server error", 
      error: error.message 
    });
  }
});

// All policies endpoint - unchanged
app.get("/addadmin", async (req, res) => {
  try {
    const options = {
      sort: { createdAt: -1 }, // Latest first
    };
    
    const allPolicies = await addadmins.find({}, options).toArray();
    
    // Add application count to all policies
    const policiesWithCount = await Promise.all(
      allPolicies.map(async (policy) => {
        const applicationCount = await amounts.countDocuments({
          policyId: policy._id.toString()
        });
        
        return {
          ...policy,
          applicationCount: applicationCount || 0
        };
      })
    );
    
    console.log("All policies response:", policiesWithCount.length);
    res.send(policiesWithCount);
    
  } catch (error) {
    console.error("Error fetching all policies:", error);
    res.status(500).send({ 
      message: "Failed to fetch all policies", 
      error: error.message 
    });
  }
});

// Update SendParcel to include policyId reference
app.post("/SendParcel", async (req, res) => {
  try {
    const data = req.body;
    
    // Add unique identifier and timestamp
    const applicationData = {
      ...data,
      applicationId: `APP-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      submissionDate: new Date().toISOString(),
      creation_date: new Date().toISOString(),
      // Add policy reference if provided
      policyId: data.policyId || null,
    };
    
    const result = await amounts.insertOne(applicationData);
    
    if (result.insertedId) {
      res.send({ 
        insertedId: result.insertedId,
        message: "Application submitted successfully",
        applicationId: applicationData.applicationId
      });
    } else {
      res.status(500).send({ message: "Failed to submit application" });
    }
    
  } catch (error) {
    console.error("Error inserting application:", error);
    res.status(500).send({ 
      message: "Internal server error", 
      error: error.message 
    });
  }
});

// Get policy application statistics
app.get("/addadmin/:id/stats", async (req, res) => {
  try {
    const policyId = req.params.id;
    
    if (!ObjectId.isValid(policyId)) {
      return res.status(400).send({ message: "Invalid policy ID format" });
    }
    
    const applicationCount = await amounts.countDocuments({
      policyId: policyId
    });
    
    const recentApplications = await amounts.find({
      policyId: policyId
    })
    .sort({ creation_date: -1 })
    .limit(5)
    .toArray();
    
    res.send({
      policyId,
      applicationCount,
      recentApplications: recentApplications.map(app => ({
        id: app._id,
        email: app.email,
        submissionDate: app.submissionDate,
        status: app.payment_status || 'pending'
      }))
    });
    
  } catch (error) {
    console.error("Error fetching policy stats:", error);
    res.status(500).send({ 
      message: "Failed to fetch policy statistics", 
      error: error.message 
    });
  }
});
        // my st 
        app.post('/addadmin', async (req, res) => {
            try {
                const policy = req.body;
                const result = await addadmins.insertOne(policy);
                res.status(201).send(result);
            } catch (error) {
                res.status(500).send({ message: 'Failed to add addadmin', error });
            }
        });

        // GET: All policies (optional, for frontend list)
        app.get('/addadmin', async (req, res) => {
            try {
                const result = await addadmins.find().toArray();
                res.send(result);
            } catch (error) {
                res.status(500).send({ message: 'Failed to fetch addadmin', error });
            }
        });
      
        app.get('/addadmin/:id', async (req, res) => {
            const id = req.params.id;

            try {
                const policy = await addadmins.findOne({ _id: new ObjectId(id) });

                if (!policy) {
                    return res.status(404).send({ message: 'Policy not found' });
                }

                res.send(policy);
            } catch (error) {
                res.status(500).send({ message: 'Failed to fetch policy', error });
            }
        });

        // my end

        app.patch("/parcels/:id/cashout", async (req, res) => {
            const id = req.params.id;
            const result = await parcelsCollection.updateOne(
                { _id: new ObjectId(id) },
                {
                    $set: {
                        cashout_status: "cashed_out",
                        cashed_out_at: new Date()
                    }
                }
            );
            res.send(result);
        });



        app.delete('/parcels/:id', async (req, res) => {
            try {
                const id = req.params.id;

                const result = await parcelsCollection.deleteOne({ _id: new ObjectId(id) });

                res.send(result);
            } catch (error) {
                console.error('Error deleting parcel:', error);
                res.status(500).send({ message: 'Failed to delete parcel' });
            }
        });

        app.get("/trackings/:trackingId", async (req, res) => {
            const trackingId = req.params.trackingId;

            const updates = await trackingsCollection
                .find({ tracking_id: trackingId })
                .sort({ timestamp: 1 }) // sort by time ascending
                .toArray();

            res.json(updates);
        });

        app.post("/trackings", async (req, res) => {
            const update = req.body;

            update.timestamp = new Date(); // ensure correct timestamp
            if (!update.tracking_id || !update.status) {
                return res.status(400).json({ message: "tracking_id and status are required." });
            }

            const result = await trackingsCollection.insertOne(update);
            res.status(201).json(result);
        });

        app.post('/riders', async (req, res) => {
            const rider = req.body;
            const result = await ridersCollection.insertOne(rider);
            res.send(result);
        })

        app.get("/riders/pending", verifyFBToken, verifyAdmin, async (req, res) => {
            try {
                const pendingRiders = await ridersCollection
                    .find({ status: "pending" })
                    .toArray();

                res.send(pendingRiders);
            } catch (error) {
                console.error("Failed to load pending riders:", error);
                res.status(500).send({ message: "Failed to load pending riders" });
            }
        });

        app.get("/riders/active", verifyFBToken, verifyAdmin, async (req, res) => {
            const result = await ridersCollection.find({ status: "active" }).toArray();
            res.send(result);
        });

        app.get("/riders/available", async (req, res) => {
            const { district } = req.query;

            try {
                const riders = await ridersCollection
                    .find({
                        district,
                        // status: { $in: ["approved", "active"] },
                        // work_status: "available",
                    })
                    .toArray();

                res.send(riders);
            } catch (err) {
                res.status(500).send({ message: "Failed to load riders" });
            }
        });

        app.patch("/riders/:id/status", async (req, res) => {
            const { id } = req.params;
            const { status, email } = req.body;
            const query = { _id: new ObjectId(id) }
            const updateDoc = {
                $set:
                {
                    status
                }
            }

            try {
                const result = await ridersCollection.updateOne(
                    query, updateDoc

                );

                // update user role for accepting rider
                if (status === 'active') {
                    const userQuery = { email };
                    const userUpdateDoc = {
                        $set: {
                            role: 'rider'
                        }
                    };
                    const roleResult = await usersCollection.updateOne(userQuery, userUpdateDoc)
                    console.log(roleResult.modifiedCount)
                }

                res.send(result);
            } catch (err) {
                res.status(500).send({ message: "Failed to update rider status" });
            }
        });


        app.post("/tracking", async (req, res) => {
            const { tracking_id, parcel_id, status, message, updated_by = '' } = req.body;

            const log = {
                tracking_id,
                parcel_id: parcel_id ? new ObjectId(parcel_id) : undefined,
                status,
                message,
                time: new Date(),
                updated_by,
            };

            const result = await trackingCollection.insertOne(log);
            res.send({ success: true, insertedId: result.insertedId });
        });


       // GET: Fetch payment history (already protected)
app.get('/payments', async (req, res) => {
  try {
    const userEmail = req.query.email;
    console.log('decoded', req.decoded);
console.log(userEmail);
    // if (req.decoded.email !== userEmail) {
    //   return res.status(403).send({ message: 'forbidden access' });
    // }

    const query = userEmail ? { email: userEmail } : {};
    const options = { sort: { paid_at: -1 } };

    const payments = await paymentsCollection.find(query, options).toArray();
    res.send(payments);
  } catch (error) {
    console.error('Error fetching payment history:', error);
    res.status(500).send({ message: 'Failed to get payments' });
  }
});

//  POST: Record payment and update parcel status (SECURED NOW)
// app.post('/payments', async (req, res) => {
//   try {
//     const { parcelId, email, amount, transactionId, paymentMethod } = req.body;
    
//     // Validate required fields
//     if (!parcelId || !email || !amount || !transactionId) {
//       return res.status(400).send({ 
//         message: "All payment fields are required" 
//       });
//     }
    
//     // Record payment
//     const paymentData = {
//       parcelId,
//       email,
//       amount,
//       transactionId,
//       paymentMethod,
//       status: 'completed',
//       createdAt: new Date()
//     };
    
//     const paymentResult = await paymentsCollection.insertOne(paymentData);
    
//     // Update parcel payment status
//     const updateResult = await amounts.updateOne(
//       { _id: new ObjectId(parcelId) },
//       { 
//         $set: { 
//           payment_status: 'paid',
//           status: 'processing',
//           paidAt: new Date(),
//           transactionId: transactionId
//         }
//       }
//     );
    
//     if (updateResult.modifiedCount === 0) {
//       throw new Error("Failed to update parcel status");
//     }
    
//     res.send({ 
//       insertedId: paymentResult.insertedId,
//       message: "Payment recorded successfully"
//     });
    
//   } catch (error) {
//     console.error('Payment recording error:', error);
//     res.status(500).send({ 
//       message: "Payment recording failed",
//       error: error.message 
//     });
//   }
// });

//  Stripe Payment Intent
// app.post('/create-payment-intent', async (req, res) => {
//   try {
//     const { amountInCents, parcelId } = req.body;
    
//     // Validate inputs
//     if (!amountInCents || !parcelId) {
//       return res.status(400).send({ 
//         message: "Amount and parcel ID are required" 
//       });
//     }
    
//     // Verify parcel exists and amount matches
//     const parcel = await amounts.findOne({ _id: new ObjectId(parcelId) });
//     if (!parcel) {
//       return res.status(404).send({ message: "Parcel not found" });
//     }
    
//     const expectedAmountCents = Math.round(parseFloat(parcel.cost) * 100);
//     if (amountInCents !== expectedAmountCents) {
//       return res.status(400).send({ 
//         message: "Amount mismatch",
//         expected: expectedAmountCents,
//         received: amountInCents
//       });
//     }
    
//     // Create payment intent
//     const paymentIntent = await stripe.paymentIntents.create({
//       amount: amountInCents,
//       currency: 'bdt',
//       metadata: {
//         parcelId: parcelId,
//         userEmail: parcel.email
//       }
//     });
    
//     res.send({ clientSecret: paymentIntent.client_secret });
//   } catch (error) {
//     console.error('Payment intent creation error:', error);
//     res.status(500).send({ 
//       message: "Payment intent creation failed",
//       error: error.message 
//     });
//   }
// });
// Payment Intent Creation API - এটি আপনার existing server code এ যোগ করুন
app.post('/create-payment-intent', async (req, res) => {
    try {
        const { amountInCents, parcelId } = req.body;
        
        console.log('Creating payment intent for:', { amountInCents, parcelId });
        
        // Minimum amount check for Stripe (50 cents minimum)
        const minimumAmount = 50; // 50 cents in USD
        const finalAmount = Math.max(amountInCents, minimumAmount);
        
        if (finalAmount < minimumAmount) {
            return res.status(400).send({
                message: 'Payment amount too low',
                error: `Minimum payment amount is 50 cents. Current amount: ${amountInCents} cents`
            });
        }

        // Verify parcel exists
        const parcel = await amounts.findOne({ _id: new ObjectId(parcelId) });
        if (!parcel) {
            return res.status(404).send({ message: 'Parcel not found' });
        }

        // Create payment intent with Stripe
        const paymentIntent = await stripe.paymentIntents.create({
            amount: finalAmount, // Amount in cents
            currency: 'usd', // Stripe requires USD for international payments
            metadata: {
                parcelId: parcelId.toString(),
                originalAmount: amountInCents.toString()
            }
        });

        res.send({
            clientSecret: paymentIntent.client_secret,
            amount: finalAmount
        });

    } catch (error) {
        console.error('Payment intent creation error:', error);
        res.status(500).send({
            message: 'Payment intent creation failed',
            error: error.message
        });
    }
});

// Payments Recording API - এটিও যোগ করুন
app.post('/payments', async (req, res) => {
    try {
        const { parcelId, email, amount, transactionId, paymentMethod } = req.body;
        
        console.log('Recording payment:', { parcelId, email, amount, transactionId });
        
        // Record payment in payments collection
        const paymentData = {
            parcelId,
            email,
            amount: parseFloat(amount),
            transactionId,
            paymentMethod,
            paymentDate: new Date(),
            status: 'completed'
        };
        
        const paymentResult = await paymentsCollection.insertOne(paymentData);
        
        // Update parcel payment status
        const updateResult = await amounts.updateOne(
            { _id: new ObjectId(parcelId) },
            { 
                $set: { 
                    payment_status: 'paid',
                    transactionId: transactionId,
                    paymentDate: new Date()
                }
            }
        );
        
        console.log('Payment recorded and parcel updated:', { paymentResult, updateResult });
        
        if (paymentResult.insertedId && updateResult.modifiedCount > 0) {
            res.send({ 
                insertedId: paymentResult.insertedId,
                message: 'Payment recorded successfully',
                parcelUpdated: true
            });
        } else {
            res.status(400).send({ message: 'Failed to record payment or update parcel' });
        }
        
    } catch (error) {
        console.error('Payment recording error:', error);
        res.status(500).send({
            message: 'Payment recording failed',
            error: error.message
        });
    }
});



        // Send a ping to confirm a successful connection
        // await client.db("admin").command({ ping: 1 });
        // console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);



// Sample route
app.get('/', (req, res) => {
    res.send('Parcel Server is running');
});

// Start the server
app.listen(port, () => {
    console.log(`Server is listening on port ${port}`);
});