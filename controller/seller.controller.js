import jwt from "jsonwebtoken";

// Helper: check if request is from mobile app
const isMobileRequest = (req) => req.headers["x-mobile-app"] === "true";

// seller login : /api/seller/login
export const sellerLogin = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      password === process.env.SELLER_PASSWORD &&
      email === process.env.SELLER_EMAIL
    ) {
      const token = jwt.sign({ email }, process.env.JWT_SECRET, {
        expiresIn: "7d",
      });

      if (isMobileRequest(req)) {
        // Mobile -> send token in JSON
        return res.status(200).json({
          message: "Login successful (mobile)",
          success: true,
          token,
        });
      } else {
        // Web -> set cookie 
        res.cookie("sellerToken", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "Strict",
          path: "/",
          maxAge: 7 * 24 * 60 * 60 * 1000,
        });
        return res.status(200).json({
          message: "Login successful",
          success: true,
        });
      }
    } else {
      return res
        .status(400)
        .json({ message: "Invalid credentials", success: false });
    }
  } catch (error) {
    console.error("Error in sellerLogin:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// check seller auth : /api/seller/is-auth
export const checkAuth = async (req, res) => {
  try {
    if (isMobileRequest(req)) {
      const authHeader = req.headers.authorization;
      if (!authHeader)
        return res.status(401).json({ message: "Unauthorized" });
      const token = authHeader.split(" ")[1];
      try {
        jwt.verify(token, process.env.JWT_SECRET);
      } catch {
        return res.status(401).json({ message: "Invalid token" });
      }
    } else {
      // Web -> cookie based
    }

    res.status(200).json({
      success: true,
    });
  } catch (error) {
    console.error("Error in checkAuth:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// logout seller: /api/seller/logout
export const sellerLogout = async (req, res) => {
  try {
    if (isMobileRequest(req)) {
      // Mobile -> just return success
      return res.status(200).json({
        message: "Logged out successfully (mobile)",
        success: true,
      });
    } else {
      // Web -> clear cookie
      res.clearCookie("sellerToken", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "none" : "Strict",
        path: "/",
      });
      return res.status(200).json({
        message: "Logged out successfully",
        success: true,
      });
    }
  } catch (error) {
    console.error("Error in sellerLogout:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};
