
const mongoose = require("mongoose");

const EmergencyAlertSchema = new mongoose.Schema({
    patientId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    alertMessage: String,
    date: { type: Date, default: Date.now },
});

module.exports = mongoose.model("EmergencyAlert", EmergencyAlertSchema);
