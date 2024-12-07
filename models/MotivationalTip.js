const { default: mongoose } = require("mongoose");

const motivationalTipSchema = new mongoose.Schema({
    nurseId:{type:mongoose.Schema.Types.ObjectId,ref:"User"},
    tip:String,
    date:{type:Date,default:Date.now}
})
module.exports = mongoose.model("MotivationTip",motivationalTipSchema)