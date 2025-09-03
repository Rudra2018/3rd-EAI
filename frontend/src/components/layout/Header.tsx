'use client';

import { useState, useEffect } from 'react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { FileText } from 'lucide-react';

export default function Header() {
  const [token, setToken] = useState('');

  useEffect(() => {
    const storedToken = localStorage.getItem('token');
    if (storedToken) {
      setToken(storedToken);
    }
  }, []);

  const handleTokenChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newToken = e.target.value;
    setToken(newToken);
    if (typeof window !== 'undefined') {
      localStorage.setItem('token', newToken);
    }
  };

  return (
    <header className="flex justify-between items-center p-4 border-b border-gray-200 dark:border-gray-800">
      <div className="flex items-center space-x-2">
        <h1 className="text-xl font-bold text-gray-900 dark:text-white">Rudra's Third Eye</h1>
      </div>
      <div className="flex items-center space-x-2">
        <Input
          type="text"
          placeholder="Bearer JWT (optional)"
          value={token}
          onChange={handleTokenChange}
          className="w-48"
        />
        <Button variant="outline" asChild>
          <a href="https://github.com/ankitthakur/rudra-third-eye-api-scanner" target="_blank" rel="noopener noreferrer">
            <FileText className="h-4 w-4 mr-2" />
            Docs
          </a>
        </Button>
      </div>
    </header>
  );
}
