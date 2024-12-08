const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const VitalSign = require("../models/VitalSign");
const MotivationalTip = require("../models/MotivationalTip");
const EmergencyAlert = require("../models/EmergencyAlert");

module.exports = {
    // User Registration
    registerUser: async ({ input }) => {
        try {
            // Check if the user already exists by email (assuming email is unique)
            const existingUser = await User.findOne({ email: input.email });
            if (existingUser) {
                throw new Error('User with this email already exists');
            }
    
            // Hash the user's password using bcrypt (12 salt rounds)
            const hashedPassword = await bcrypt.hash(input.password, 12);
    
            // Create a new user with the input data and the hashed password
            const user = new User({
                ...input, // Spread the input data (e.g., username, email, etc.)
                password: hashedPassword // Replace the plain-text password with the hashed password
            });
    
            // Save the new user to the database
            const savedUser = await user.save();
    
            // Return the saved user data (you can omit sensitive fields like password)
            return {
                id: savedUser._id,
                email: savedUser.email,
                username: savedUser.username,
                createdAt: savedUser.createdAt
            };
        } catch (error) {
            // Handle any errors (e.g., hashing failure, DB issues, user already exists)
            throw new Error('User registration failed: ' + error.message);
        }
    }
    

    // User Login
    login: async ({ email, password }) => {
        const user = await User.findOne({ email });
        if (!user) throw new Error("User not found");

        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) throw new Error("Invalid credentials");

        // Return JWT Token
        return jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1h" });
    },

    // Nurse: Add Vital Signs
    addVitalSign: async ({ input }, req) => {
        if (!req.user || req.user.role !== "nurse") {
            throw new Error("Unauthorized: Only nurses can add vital signs.");
        }

        const vitalSign = new VitalSign(input);
        return await vitalSign.save();
    },

    // Nurse: Add Motivational Tip
    addMotivationalTip: async ({ tip }, req) => {
        if (!req.user || req.user.role !== "nurse") {
            throw new Error("Unauthorized: Only nurses can add motivational tips.");
        }

        const newTip = new MotivationalTip({ nurseId: req.user.id, tip });
        return await newTip.save();
    },

    // Patient: Send //Emergency Alert
    sendEmergencyAlert: async ({ alertMessage }, req) => {
        if (!req.user || req.user.role !== "patient") {
            throw new Error("Unauthorized: Only patients can send emergency alerts.");
        }

        const alert = new EmergencyAlert({ patientId: req.user.id, alertMessage });
        return await alert.save();
    },

    // Nurse: Get Vital Signs for a Patient
    getVitalSigns: async ({ patientId }, req) => {
        if (!req.user || req.user.role !== "nurse") {
            throw new Error("Unauthorized: Only nurses can view vital signs.");
        }

        return await VitalSign.find({ patientId });
    },

    // Nurse: Get Motivational Tips
    getMotivationalTips: async (args, req) => {
        if (!req.user || req.user.role !== "nurse") {
            throw new Error("Unauthorized: Only nurses can view motivational tips.");
        }

        return await MotivationalTip.find();
    },
};
