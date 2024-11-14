import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

export default (req, res, next) => {
  // look/pull token from the header
  const token = req.header('x-auth-token');

  // If token is not found
  if (!token) {
    return res.status(401).json({ errors: [{ msg: 'No Token, Auth Denied' }] });
  }

  try {
    // Does our jwt secret match the jwt secret in the token?
    const decoded = jwt.verify(token, process.env.jwtSecret);

    req.user = decoded.user;

    next()

  } catch (err) {
    console.error(err);
    res.status(401).json({ errors: [{ msg: 'Token is not valid' }] });
  }
};
