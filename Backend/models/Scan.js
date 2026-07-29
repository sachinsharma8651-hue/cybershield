const mongoose = require("mongoose");

const scanSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    input: {
      type: String,
      required: true,
    },

    type: {
      type: String,
      enum: ["url", "text"],
      required: true,
    },

    riskScore: {
      type: Number,
      default: 0,
    },

    isSecure: Boolean,

    usesHTTPS: Boolean,

    result: {
      type: Object,
      required: true,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("Scan", scanSchema);