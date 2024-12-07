const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const { MongoMemoryServer } = require("mongodb-memory-server");
const User = require("../models/User");
const VitalSign = require("../models/VitalSign");
const MotivationalTip = require("../models/MotivationalTip");
const EmergencyAlert = require("../models/EmergencyAlert");
const controller = require("../resolvers/resolvers"); // Adjust the path to your controller file

let mongoServer;

describe("Controller Tests", () => {
    beforeAll(async () => {
        process.env.JWT_SECRET = "test-secret"; // Set a mock secret for testing
        mongoServer = await MongoMemoryServer.create();
        const uri = mongoServer.getUri();
        await mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true });
    });

    afterAll(async () => {
        await mongoose.disconnect();
        await mongoServer.stop();
    });

    beforeEach(async () => {
        await User.deleteMany();
        await VitalSign.deleteMany();
        await MotivationalTip.deleteMany();
        await EmergencyAlert.deleteMany();
    });

    it("should register a new user", async () => {
        const input = { name: "Test User", email: "test@example.com", password: "password123", role: "patient" };

        const user = await controller.registerUser({ input });

        expect(user).toHaveProperty("_id");
        expect(user.email).toBe(input.email);

        // Verify password is hashed
        const isPasswordCorrect = await bcrypt.compare(input.password, user.password);
        expect(isPasswordCorrect).toBe(true);
    });

    it("should login a user and return a token", async () => {
        // Correct input object with all required fields
        const input = { 
            name: "Test User", 
            email: "test@example.com", 
            password: "password123", 
            role: "patient" 
        };
    
        // Hash the password and create a user
        const hashedPassword = await bcrypt.hash(input.password, 12);
        const user = new User({ ...input, password: hashedPassword });
        await user.save();
    
        // Test the login function
        const token = await controller.login({ email: input.email, password: input.password });
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
        // Assertions
        expect(decoded).toHaveProperty("id", user._id.toString());
        expect(decoded).toHaveProperty("role", user.role);
    });
    

    it("should add vital signs by a nurse", async () => {
        const nurse = new User({ 
            name: "Nurse Test", 
            email: "nurse@example.com", 
            password: "hashed", 
            role: "nurse" 
        });
        await nurse.save();
    
        const req = { user: { id: nurse._id, role: "nurse" } };
        const input = { 
            patientId: new mongoose.Types.ObjectId(), 
            temperature: 98.6, 
            heartRate: 72, 
            bloodPressure: "120/80", 
            respiratoryRate: 16 
        };
    
        const vitalSign = await controller.addVitalSign({ input }, req);
    
        expect(vitalSign).toHaveProperty("_id");
        expect(vitalSign.heartRate).toBe(input.heartRate);
        expect(vitalSign.bloodPressure).toBe(input.bloodPressure);
    });
    
    
    it("should throw error when unauthorized user tries to add vital signs", async () => {
        const req = { user: { id: new mongoose.Types.ObjectId(), role: "patient" } }; // Add 'new'
        const input = { patientId: new mongoose.Types.ObjectId(), heartRate: 72, bloodPressure: "120/80" }; // Add 'new'
    
        await expect(controller.addVitalSign({ input }, req)).rejects.toThrow("Unauthorized: Only nurses can add vital signs.");
    });
    

    it("should send emergency alert by a patient", async () => {
        const patient = new User({ 
            name: "Patient Test",  // Add 'name'
            email: "patient@example.com", 
            password: "hashed", 
            role: "patient" 
        });
        await patient.save();
    
        const req = { user: { id: patient._id, role: "patient" } };
        const alertMessage = "Help needed immediately!";
    
        const alert = await controller.sendEmergencyAlert({ alertMessage }, req);
    
        expect(alert).toHaveProperty("_id");
        expect(alert.alertMessage).toBe(alertMessage);
    });
    
});
