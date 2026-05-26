require("dotenv").config();

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

const {
  MongoClient,
  ServerApiVersion,
  ObjectId,
} = require("mongodb");

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.4xpowit.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// JWT
app.post("/jwt", async (req, res) => {
  const user = req.body;

  const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "7d",
  });

  res.send({ token });
});

// Verify Token
const verifyToken = (req, res, next) => {
  if (!req.headers.authorization) {
    return res.status(401).send({
      message: "Unauthorized access",
    });
  }

  const token = req.headers.authorization.split(" ")[1];

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send({
        message: "Unauthorized access",
      });
    }

    req.decoded = decoded;
    next();
  });
};

async function run() {
  try {
    const database = client.db("contestHubDB");

    const usersCollection = database.collection("users");
    const contestsCollection = database.collection("contests");
    const paymentsCollection = database.collection("payments");
    const submissionsCollection = database.collection("submissions");

    // Verify Admin
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;

      const user = await usersCollection.findOne({ email });

      if (!user || user.role !== "admin") {
        return res.status(403).send({
          message: "Forbidden access",
        });
      }

      next();
    };

    // Verify Creator
    const verifyCreator = async (req, res, next) => {
      const email = req.decoded.email;

      const user = await usersCollection.findOne({ email });

      if (!user || user.role !== "creator") {
        return res.status(403).send({
          message: "Forbidden access",
        });
      }

      next();
    };

    // ======================
    // USERS
    // ======================

    app.post("/users", async (req, res) => {
      const user = req.body;

      if (!user?.email) {
        return res.status(400).send({
          message: "User email is required",
        });
      }

      const existingUser = await usersCollection.findOne({
        email: user.email,
      });

      if (existingUser) {
        return res.send({
          message: "User already exists",
          insertedId: null,
        });
      }

      const newUser = {
        name: user.name || "No Name",
        email: user.email,
        photo: user.photo || "",
        role: "user",
        createdAt: new Date(),
      };

      const result = await usersCollection.insertOne(newUser);
      res.send(result);
    });

    app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
      const result = await usersCollection.find().toArray();
      res.send(result);
    });

    app.get("/users/role/:email", verifyToken, async (req, res) => {
      const email = req.params.email;

      if (email !== req.decoded.email) {
        return res.status(403).send({
          message: "Forbidden access",
        });
      }

      const user = await usersCollection.findOne({ email });

      res.send({
        role: user?.role || "user",
      });
    });

    // Temporary: make first admin
    app.patch("/users/admin/:email", async (req, res) => {
      const email = req.params.email;

      const result = await usersCollection.updateOne(
        { email },
        {
          $set: {
            role: "admin",
          },
        }
      );

      res.send(result);
    });

    app.patch("/users/role/:id", verifyToken, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const { role } = req.body;

      if (!["user", "creator", "admin"].includes(role)) {
        return res.status(400).send({
          message: "Invalid role",
        });
      }

      const result = await usersCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            role,
          },
        }
      );

      res.send(result);
    });

    // ======================
    // CONTESTS
    // ======================

    app.post("/contests", verifyToken, verifyCreator, async (req, res) => {
      const contest = req.body;

      const newContest = {
        name: contest.name,
        image: contest.image,
        description: contest.description,
        price: parseFloat(contest.price),
        prizeMoney: parseFloat(contest.prizeMoney),
        taskInstruction: contest.taskInstruction,
        contestType: contest.contestType,
        deadline: contest.deadline,

        creatorEmail: req.decoded.email,
        creatorName: contest.creatorName,

        status: "pending",
        participantsCount: 0,

        winnerEmail: null,
        winnerName: null,
        winnerPhoto: null,

        createdAt: new Date(),
      };

      const result = await contestsCollection.insertOne(newContest);
      res.send(result);
    });

    app.get("/contests/approved", async (req, res) => {
      const result = await contestsCollection
        .find({ status: "confirmed" })
        .sort({ participantsCount: -1 })
        .toArray();

      res.send(result);
    });

    app.get("/contests", verifyToken, verifyAdmin, async (req, res) => {
      const result = await contestsCollection
        .find()
        .sort({ createdAt: -1 })
        .toArray();

      res.send(result);
    });

    app.get(
      "/contests/creator/:email",
      verifyToken,
      verifyCreator,
      async (req, res) => {
        const email = req.params.email;

        if (email !== req.decoded.email) {
          return res.status(403).send({
            message: "Forbidden access",
          });
        }

        const result = await contestsCollection
          .find({ creatorEmail: email })
          .sort({ createdAt: -1 })
          .toArray();

        res.send(result);
      }
    );

    app.get("/contests/:id", async (req, res) => {
      const id = req.params.id;

      const result = await contestsCollection.findOne({
        _id: new ObjectId(id),
      });

      res.send(result);
    });

    app.patch(
      "/contests/approve/:id",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;

        const result = await contestsCollection.updateOne(
          { _id: new ObjectId(id) },
          {
            $set: {
              status: "confirmed",
            },
          }
        );

        res.send(result);
      }
    );

    app.patch(
      "/contests/reject/:id",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;

        const result = await contestsCollection.updateOne(
          { _id: new ObjectId(id) },
          {
            $set: {
              status: "rejected",
            },
          }
        );

        res.send(result);
      }
    );

    app.delete("/contests/:id", verifyToken, verifyAdmin, async (req, res) => {
      const id = req.params.id;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          message: "Invalid contest id",
        });
      }

      const result = await contestsCollection.deleteOne({
        _id: new ObjectId(id),
      });

      res.send(result);
    });
    // ======================
    // PAYMENTS
    // ======================

    app.post("/create-payment-intent", verifyToken, async (req, res) => {
      const { price } = req.body;

      const amount = parseInt(price * 100);

      const paymentIntent = await stripe.paymentIntents.create({
        amount,
        currency: "usd",
        payment_method_types: ["card"],
      });

      res.send({
        clientSecret: paymentIntent.client_secret,
      });
    });

    app.post("/payments", verifyToken, async (req, res) => {
      const payment = req.body;

      const existingPayment = await paymentsCollection.findOne({
        contestId: payment.contestId,
        userEmail: payment.userEmail,
      });

      if (existingPayment) {
        return res.send({
          message: "Already registered",
          insertedId: null,
        });
      }

      const paymentResult = await paymentsCollection.insertOne({
        ...payment,
        status: "paid",
        paidAt: new Date(),
      });

      await contestsCollection.updateOne(
        { _id: new ObjectId(payment.contestId) },
        {
          $inc: {
            participantsCount: 1,
          },
        }
      );

      res.send(paymentResult);
    });

    app.get("/payments/check/:contestId/:email", verifyToken, async (req, res) => {
      const { contestId, email } = req.params;

      if (email !== req.decoded.email) {
        return res.status(403).send({
          message: "Forbidden access",
        });
      }

      const payment = await paymentsCollection.findOne({
        contestId,
        userEmail: email,
      });

      res.send({
        paid: !!payment,
      });
    });

    // ======================
    // SUBMISSIONS
    // ======================

    app.post("/submissions", verifyToken, async (req, res) => {
      const submission = req.body;

      const payment = await paymentsCollection.findOne({
        contestId: submission.contestId,
        userEmail: req.decoded.email,
      });

      if (!payment) {
        return res.status(403).send({
          message: "You must register first",
        });
      }

      const existingSubmission = await submissionsCollection.findOne({
        contestId: submission.contestId,
        participantEmail: req.decoded.email,
      });

      if (existingSubmission) {
        return res.send({
          message: "Already submitted",
          insertedId: null,
        });
      }

      const result = await submissionsCollection.insertOne({
        contestId: submission.contestId,
        contestName: submission.contestName,
        participantEmail: req.decoded.email,
        participantName: submission.participantName,
        taskLink: submission.taskLink,
        isWinner: false,
        submittedAt: new Date(),
      });

      res.send(result);
    });

    // ======================
    // CREATOR SUBMISSIONS
    // ======================

    app.get("/payments/check/:contestId/:email", verifyToken, async (req, res) => {
      const { contestId, email } = req.params;

      if (email !== req.decoded.email) {
        return res.status(403).send({
          message: "Forbidden access",
        });
      }

      const payment = await paymentsCollection.findOne({
        contestId,
        userEmail: email,
      });

      res.send({
        paid: !!payment,
      });
    });

    // ======================
    // DECLARE WINNER
    // ======================

    app.patch(
      "/submissions/winner/:id",
      verifyToken,
      verifyCreator,
      async (req, res) => {

        const id = req.params.id;

        const submission = await submissionsCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!submission) {
          return res.status(404).send({
            message: "Submission not found",
          });
        }

        // reset previous winners of same contest
        await submissionsCollection.updateMany(
          {
            contestId: submission.contestId,
          },
          {
            $set: {
              isWinner: false,
            },
          }
        );

        // set current winner
        await submissionsCollection.updateOne(
          { _id: new ObjectId(id) },
          {
            $set: {
              isWinner: true,
            },
          }
        );

        // update contest winner info
        await contestsCollection.updateOne(
          {
            _id: new ObjectId(submission.contestId),
          },
          {
            $set: {
              winnerEmail: submission.participantEmail,
              winnerName: submission.participantName,
            },
          }
        );

        res.send({
          success: true,
        });
      }
    );

    // ======================
    // USER PARTICIPATED CONTESTS
    // ======================

    app.get(
      "/payments/user/:email",
      verifyToken,
      async (req, res) => {

        const email = req.params.email;

        if (email !== req.decoded.email) {
          return res.status(403).send({
            message: "Forbidden access",
          });
        }

        const result = await paymentsCollection
          .find({
            userEmail: email,
          })
          .sort({ paidAt: -1 })
          .toArray();

        res.send(result);
      }
    );

    // ======================
    // USER WINNING CONTESTS
    // ======================

    app.get(
      "/winning-contests/:email",
      verifyToken,
      async (req, res) => {

        const email = req.params.email;

        if (email !== req.decoded.email) {
          return res.status(403).send({
            message: "Forbidden access",
          });
        }

        const result = await contestsCollection
          .find({
            winnerEmail: email,
          })
          .toArray();

        res.send(result);
      }
    );

    // ======================
    // LEADERBOARD
    // ======================

   app.get("/leaderboard", async (req, res) => {
  const winners = await contestsCollection
    .find({
      winnerEmail: { $exists: true, $ne: null },
    })
    .toArray();

  const leaderboardMap = {};

  winners.forEach(contest => {
    if (!leaderboardMap[contest.winnerEmail]) {
      leaderboardMap[contest.winnerEmail] = {
        winnerName: contest.winnerName,
        winnerEmail: contest.winnerEmail,
        winnerPhoto: contest.winnerPhoto || "",
        totalWins: 0,
        totalPrize: 0,
      };
    }

    leaderboardMap[contest.winnerEmail].totalWins += 1;
    leaderboardMap[contest.winnerEmail].totalPrize += Number(contest.prizeMoney) || 0;
  });

  const leaderboard = Object.values(leaderboardMap).sort(
    (a, b) => b.totalWins - a.totalWins
  );

  res.send(leaderboard);
});


    app.get("/submissions", verifyToken, verifyAdmin, async (req, res) => {
      const result = await submissionsCollection
        .find()
        .sort({ submittedAt: -1 })
        .toArray();

      res.send(result);
    });

    app.patch("/submissions/winner/:id", verifyToken, verifyAdmin, async (req, res) => {
      const id = req.params.id;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({ message: "Invalid submission id" });
      }

      const submission = await submissionsCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!submission) {
        return res.status(404).send({ message: "Submission not found" });
      }

      await submissionsCollection.updateMany(
        { contestId: submission.contestId },
        { $set: { isWinner: false } }
      );

      await submissionsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { isWinner: true } }
      );

      await contestsCollection.updateOne(
        { _id: new ObjectId(submission.contestId) },
        {
          $set: {
            winnerEmail: submission.participantEmail,
            winnerName: submission.participantName,
            winnerPhoto: submission.participantPhoto || "",
          },
        }
      );

      res.send({
        success: true,
        winnerEmail: submission.participantEmail,
        winnerName: submission.participantName,
      });
    });

    app.get("/submissions/user/:email", verifyToken, async (req, res) => {
      const email = req.params.email;

      if (email !== req.decoded.email) {
        return res.status(403).send({
          message: "Forbidden access",
        });
      }

      const result = await submissionsCollection
        .find({ participantEmail: email })
        .sort({ submittedAt: -1 })
        .toArray();

      res.send(result);
    });


    app.get("/winning-contests/:email", verifyToken, async (req, res) => {
      const email = req.params.email;

      if (email !== req.decoded.email) {
        return res.status(403).send({
          message: "Forbidden access",
        });
      }

      const result = await contestsCollection
        .find({ winnerEmail: email })
        .sort({ createdAt: -1 })
        .toArray();

      res.send(result);
    });

    console.log("MongoDB connected");
  } finally {
    // do not close client
  }
}

run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("ContestHub server is running");
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});