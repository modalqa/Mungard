// Intentionally vulnerable Next.js page (test fixture).
export default function Profile({ bio }: { bio: string }) {
  const key = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;
  return <div dangerouslySetInnerHTML={{ __html: bio }} data-key={key} />;
}
