module.exports = (err, req, res, next) => {
  console.error(`[ERROR] ${err.message}`);
  res.status(err.statusCode || 500).json({
    error: { message: err.message || "Internal Server Error" },
  });
};