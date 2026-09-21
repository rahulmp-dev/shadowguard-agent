"use client";

import { useState, useEffect } from 'react';

// ANTI-PATTERN 1: Hardcoded API keys and service role keys in client code
const SUPABASE_URL = 'https://xyzcompany.supabase.co';
const SUPABASE_SERVICE_ROLE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InhoemNvbXBhbnkiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNjg1MDAwMDAwLCJleHAiOjIwMDEwMDAwMDB9.fake_secret_key_do_not_use';
const DATABASE_URL = 'postgresql://admin:supersecretpassword123@db.example.com:5432/production';
const AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

// ANTI-PATTERN 2: Direct database query from client component
async function fetchUsers() {
  const response = await fetch(`${SUPABASE_URL}/rest/v1/users?select=*`, {
    headers: {
      'Authorization': `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      'apikey': SUPABASE_SERVICE_ROLE_KEY,
    },
  });
  return response.json();
}

// ANTI-PATTERN 3: Direct SQL-like query construction in client code
async function searchUsers(searchTerm: string) {
  const query = `select * from users where name = '${searchTerm}' or email like '%${searchTerm}%'`;
  const response = await fetch(`${SUPABASE_URL}/rest/v1/rpc/raw_query`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ query }),
  });
  return response.json();
}

export default function UserDashboard() {
  const [users, setUsers] = useState<any[]>([]);
  const [search, setSearch] = useState('');
  const [password, setPassword] = useState('');

  useEffect(() => {
    fetchUsers().then(setUsers);
  }, []);

  const handleSearch = async () => {
    const results = await searchUsers(search);
    setUsers(results);
  };

  // ANTI-PATTERN 4: Storing sensitive data in localStorage
  const handleLogin = () => {
    localStorage.setItem('auth_token', SUPABASE_SERVICE_ROLE_KEY);
    localStorage.setItem('user_password', password);
  };

  return (
    <div>
      <h1>User Dashboard</h1>
      <input
        type="text"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        placeholder="Search users..."
      />
      <button onClick={handleSearch}>Search</button>
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <button onClick={handleLogin}>Login</button>
      <ul>
        {users.map((user: any) => (
          <li key={user.id}>{user.name} - {user.email} - {user.ssn}</li>
        ))}
      </ul>
    </div>
  );
}
