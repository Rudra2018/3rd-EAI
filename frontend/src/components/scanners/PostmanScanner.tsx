'use client';

import { useState, ChangeEvent, FormEvent } from 'react';
import { scanPostman } from '@/services/api';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { FileUp } from 'lucide-react';

export default function PostmanScanner() {
  const [file, setFile] = useState<File | null>(null);
  const [scanResult, setScanResult] = useState('');
  const [loading, setLoading] = useState(false);

  const handleFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      setFile(e.target.files[0]);
    }
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!file) return;

    setLoading(true);
    setScanResult('');

    try {
      const content = await file.text();
      const collection = JSON.parse(content);
      const result = await scanPostman(collection);
      setScanResult(JSON.stringify(result, null, 2));
    } catch (error) {
      setScanResult(`Error: ${(error as Error).message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card className="p-6 space-y-4">
      <h2 className="text-xl font-semibold">Import Postman Collection</h2>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="flex items-center space-x-2">
          <label className="flex-1 cursor-pointer bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-lg p-4 text-center border-2 border-dashed border-gray-300 dark:border-gray-600 transition-colors">
            <Input type="file" onChange={handleFileChange} className="hidden" accept=".json" />
            <div className="flex flex-col items-center">
              <FileUp className="w-8 h-8 text-gray-400 dark:text-gray-500" />
              <span className="mt-2 text-sm text-gray-500 dark:text-gray-400">
                {file ? file.name : 'Click to upload or drag & drop'}
              </span>
            </div>
          </label>
        </div>
        <Button type="submit" className="w-full" disabled={loading || !file}>
          {loading ? 'Importing...' : 'Import and Scan'}
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
