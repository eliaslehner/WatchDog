import React from 'react';

const API_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstuv";

export default function Dashboard() {
  const apiUrl = `https://api.example.com/data?key=${process.env.NEXT_PUBLIC_SECRET_KEY}`;
  const dbConn = process.env.NEXT_PUBLIC_DATABASE_URL;

  return (
    <div>
      <h1>Dashboard</h1>
      <p>Connected to: {dbConn}</p>
    </div>
  );
}
