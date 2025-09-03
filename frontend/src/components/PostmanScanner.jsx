import React, { useState } from 'react';
import { toast } from 'react-hot-toast';
import { 
  FileText, 
  Upload, 
  Play, 
  CheckCircle,
  AlertCircle
} from 'lucide-react';
import ScanProgress from './ScanProgress';

const PostmanScanner = ({ onScanStart }) => {
  const [file, setFile] = useState(null);
  const [uploadStatus, setUploadStatus] = useState('');
  const [parsedData, setParsedData] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [activeScan, setActiveScan] = useState(null);

  const handleFileUpload = async (event) => {
    const selectedFile = event.target.files[0];
    if (!selectedFile) return;

    setFile(selectedFile);
    setUploadStatus('Uploading...');

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const response = await fetch('/api/upload/postman', {
        method: 'POST',
        body: formData,
      });

      const result = await response.json();
      
      if (response.ok) {
        setUploadStatus(`Successfully uploaded! Found ${result.collection_analysis.endpoints_found} endpoints`);
        setParsedData(result.data);
        toast.success('Postman collection uploaded successfully!');
      } else {
        setUploadStatus(`Upload failed: ${result.detail}`);
        toast.error('Upload failed');
      }
    } catch (error) {
      setUploadStatus(`Upload error: ${error.message}`);
      toast.error('Upload error');
    }
  };

  const handleScan = async () => {
    if (!parsedData) {
      toast.error('Please upload a Postman collection first');
      return;
    }

    setIsScanning(true);

    try {
      const response = await fetch('/api/scan/postman', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          collection_data: parsedData,
          crew_ai_enabled: true
        }),
      });

      const result = await response.json();
      
      if (response.ok) {
        setActiveScan(result.scan_id);
        onScanStart(result.scan_id, { type: 'postman', target: file.name });
        toast.success('Postman collection scan started!');
      } else {
        throw new Error(result.detail || 'Scan failed');
      }
    } catch (error) {
      toast.error(`Scan failed: ${error.message}`);
      setIsScanning(false);
    }
  };

  const handleScanComplete = () => {
    setIsScanning(false);
    setActiveScan(null);
  };

  return (
    <div className="max-w-4xl mx-auto">
      <div className="bg-white rounded-lg shadow-lg">
        <div className="p-6 border-b">
          <h1 className="text-2xl font-bold text-gray-900 flex items-center">
            <FileText className="mr-3 text-blue-600" />
            Postman Collection Scanner
          </h1>
          <p className="text-gray-600 mt-2">
            Upload and scan your Postman collections for security vulnerabilities
          </p>
        </div>

        <div className="p-6">
          {activeScan ? (
            <ScanProgress 
              scanId={activeScan} 
              onComplete={handleScanComplete}
            />
          ) : (
            <>
              <div className="mb-8">
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Upload Postman Collection
                </label>
                <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center hover:border-blue-500 transition-colors">
                  <Upload className="mx-auto h-12 w-12 text-gray-400 mb-4" />
                  <input
                    type="file"
                    accept=".json"
                    onChange={handleFileUpload}
                    className="hidden"
                    id="file-upload"
                  />
                  <label
                    htmlFor="file-upload"
                    className="cursor-pointer bg-blue-600 text-white px-6 py-3 rounded-md hover:bg-blue-700 inline-flex items-center"
                  >
                    <FileText className="mr-2 h-5 w-5" />
                    Choose Postman Collection (.json)
                  </label>
                  {file && (
                    <div className="mt-4 p-3 bg-gray-50 rounded-md">
                      <div className="flex items-center justify-center">
                        <CheckCircle className="h-5 w-5 text-green-500 mr-2" />
                        <span className="text-sm text-gray-700">
                          Selected: {file.name}
                        </span>
                      </div>
                    </div>
                  )}
                </div>
                
                {uploadStatus && (
                  <div className={`mt-3 p-3 rounded-md flex items-center ${
                    uploadStatus.includes('Successfully') 
                      ? 'bg-green-100 text-green-700' 
                      : 'bg-red-100 text-red-700'
                  }`}>
                    {uploadStatus.includes('Successfully') ? (
                      <CheckCircle className="h-5 w-5 mr-2" />
                    ) : (
                      <AlertCircle className="h-5 w-5 mr-2" />
                    )}
                    {uploadStatus}
                  </div>
                )}
              </div>

              {parsedData && (
                <div className="mb-8">
                  <h2 className="text-lg font-semibold mb-4">Collection Overview</h2>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                    <div className="bg-blue-50 p-4 rounded-lg">
                      <h3 className="font-medium text-blue-900">Total Endpoints</h3>
                      <p className="text-2xl font-bold text-blue-600">
                        {parsedData.endpoints?.length || 0}
                      </p>
                    </div>
                    <div className="bg-green-50 p-4 rounded-lg">
                      <h3 className="font-medium text-green-900">Collections</h3>
                      <p className="text-2xl font-bold text-green-600">
                        {parsedData.collections?.length || 1}
                      </p>
                    </div>
                    <div className="bg-purple-50 p-4 rounded-lg">
                      <h3 className="font-medium text-purple-900">Variables</h3>
                      <p className="text-2xl font-bold text-purple-600">
                        {Object.keys(parsedData.variables || {}).length}
                      </p>
                    </div>
                  </div>

                  <div className="flex justify-end">
                    <button
                      onClick={handleScan}
                      disabled={isScanning}
                      className="bg-green-600 text-white px-8 py-3 rounded-md hover:bg-green-700 disabled:bg-gray-400 inline-flex items-center text-lg font-medium"
                    >
                      <Play className="mr-2 h-5 w-5" />
                      {isScanning ? 'Starting Scan...' : 'Start Security Scan'}
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default PostmanScanner;

