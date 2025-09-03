import UrlScanner from '@/components/scanners/UrlScanner';
import PostmanScanner from '@/components/scanners/PostmanScanner';

export default function Home() {
  return (
    <main className="flex-1 p-6 space-y-6 container mx-auto">
      <div className="text-center my-12">
        <h1 className="text-4xl font-extrabold text-blue-600 dark:text-blue-400">Rudra's Third Eye</h1>
        <p className="mt-2 text-lg text-gray-600 dark:text-gray-400 max-w-2xl mx-auto">
          AI-powered API security scanner and autonomous bug bounty tool.
        </p>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <UrlScanner />
        <PostmanScanner />
      </div>
    </main>
  );
}
