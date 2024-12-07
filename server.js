const express = require("express");
const { graphqlHTTP } = require("express-graphql");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const auth = require("./middleware/auth");
const cors = require("cors")
const schema = require("./schema/schema");
const resolvers = require("./resolvers/resolvers");

dotenv.config();

const app = express();
app.use(cors())
app.use(express.json());
app.use(auth); // Use the auth middleware globally

app.use("/graphql", graphqlHTTP((req) => {
    // Log the user object attached by middleware
    console.log("User object in context:", req.user);

    return {
        schema,
        rootValue: resolvers,
        graphiql: true,
        context: { user: req.user }, // Pass user info to resolvers
    };
}));


mongoose.connect("mongodb://localhost:27017/GroupProject", { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => app.listen(5000, () => console.log("Server running on port 5000")))
    .catch((err) => console.error(err));
