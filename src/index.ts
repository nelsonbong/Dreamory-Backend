import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import userRoutes from './routes/user.routes';
import eventRoutes from './routes/event.routes';
import publicEventRoutes from './routes/publicEvent.routes';

import prisma from './config/prisma';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5050;

app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true,
}));
app.use(express.json());

// ✅ Routes
app.use('/auth', userRoutes);
app.use('/events', eventRoutes);
app.use('/public-events', publicEventRoutes);

// ✅ Root route for browser access
app.get('/', async (req, res) => {
  try {
    await prisma.$connect();
    res.send('✅ Express is running and connected to the database successfully!');
  } catch (err) {
    res.status(500).send('❌ Express is running but failed to connect to the database.');
  }
});

// ✅ Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
