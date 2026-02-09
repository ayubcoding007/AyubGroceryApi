import jwt from "jsonwebtoken";

// Helper: check if request is from mobile app
const isMobileRequest = (req) => req.headers["x-mobile-app"] === "true";

export const authSeller = async (req, res, next) => {
  try {
    if (isMobileRequest(req)) {
      // Mobile app -> token from Authorization header
      const authHeader = req.headers.authorization;
      if (!authHeader)
        return res.status(401).json({ message: "Unauthorized", success: false });

      const token = authHeader.split(" ")[1];
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded.email === process.env.SELLER_EMAIL) {
          return next();
        } else {
          return res.status(403).json({ message: "Forbidden", success: false });
        }
      } catch {
        return res.status(401).json({ message: "Invalid token", success: false });
      }
    } else {
      // Web -> cookie based 
      const { sellerToken } = req.cookies;
      if (!sellerToken) {
        return res.status(401).json({ message: "Unauthorized", success: false });
      }
      try {
        const decoded = jwt.verify(sellerToken, process.env.JWT_SECRET);
        if (decoded.email === process.env.SELLER_EMAIL) {
          return next();
        } else {
          return res.status(403).json({ message: "Forbidden", success: false });
        }
      } catch (error) {
        console.error("Error in authSeller middleware:", error);
        return res.status(401).json({ message: "Invalid token", success: false });
      }
    }
  } catch (error) {
    console.error("Error in authSeller middleware:", error);
    return res.status(500).json({ message: "Internal server error", success: false });
  }
};
