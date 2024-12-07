const mongoose = require("mongoose");

const DailyInfoSchema = new mongoose.Schema({
    patientId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    weight: Number,
    bloodPressure: String,
    pulseRate: Number,
    respiratoryRate: Number,
    date: { type: Date, default: Date.now },
});

module.exports = mongoose.model("DailyInfo", DailyInfoSchema);
