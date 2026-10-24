// Intentionally vulnerable Next.js route handler (test fixture).
import { readFile } from "node:fs/promises";
import fs from "node:fs";

export async function GET(request: Request) {
  const url = new URL(request.url);
  const name = url.searchParams.get("name");
  const data = fs.readFileSync("/srv/files/" + name);
  return new Response(data);
}

export async function POST(request: Request) {
  const prisma = (globalThis as any).prisma;
  const body = await request.json();
  const user = await prisma.user.create({ data: await request.json() });
  const rows = await prisma.$queryRawUnsafe(`SELECT * FROM orders WHERE id = ${body.id}`);
  return Response.json({ user, rows });
}
