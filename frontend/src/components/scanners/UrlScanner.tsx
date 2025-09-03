'use client';

import { useState, FormEvent } from 'react';
import { scanUrl } from '@/services/api';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';

export default function UrlScanner() {
  const [url, setUrl] = useState('');
  const [scanResult, setScanResult] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setScanResult('');
    try {
      const result = await scanUrl({ url });
      setScanResult(JSON.stringify(result, null, 2));
    } catch (error) {
      setScanResult(`Error: ${(error as Error).message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card className="p-6 space-y-4">
      <h2 className="text-xl font-semibold">Quick URL Scan</h2>
      <form onSubmit={handleSubmit} className="space-y-4">
        <Input
          type="url"
          placeholder="https://api.example.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          required
        />
        <Button type="submit" className="w-full" disabled={loading}>
          {loading ? 'Scanning...' : 'Run Scan'}
        </Button>
      </form>
      {scanResult && (
        <div className="pt-4">
          <h3 className="font-medium text-lg">Scan Result</h3>
          <Textarea
            readOnly
            value={scanResult}
            className="mt-2 font-mono h-64"
          />
        </div>
      )}
    </Card>
  );
}
