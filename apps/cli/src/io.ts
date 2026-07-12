import { open } from "node:fs/promises";

export class CliError extends Error {
  readonly code: string;
  readonly exitCode: number;
  readonly details?: unknown;

  constructor(code: string, message: string, exitCode: number, details?: unknown) {
    super(message);
    this.name = "CliError";
    this.code = code;
    this.exitCode = exitCode;
    this.details = details;
  }
}

export async function readUtf8File(path: string, maxBytes = 1_048_576): Promise<string> {
  let handle;
  try {
    handle = await open(path, "r");
    const stat = await handle.stat();
    if (stat.size > maxBytes) {
      throw new CliError("INPUT_TOO_LARGE", "Input file exceeds the size limit.", 2);
    }
    return await handle.readFile("utf8");
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError("FILE_READ_FAILED", "Unable to read the requested file.", 2);
  } finally {
    await handle?.close();
  }
}

export async function readJsonFile(path: string, maxBytes?: number): Promise<unknown> {
  const source = await readUtf8File(path, maxBytes);
  try {
    return JSON.parse(source) as unknown;
  } catch {
    throw new CliError("JSON_INVALID", "Input file is not valid JSON.", 2);
  }
}

export function emitJson(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

export function emitHuman(message: string): void {
  process.stdout.write(`${message}\n`);
}

export function safeFailure(error: unknown): {
  readonly code: string;
  readonly message: string;
  readonly exitCode: number;
  readonly details?: unknown;
} {
  if (error instanceof CliError) {
    return {
      code: error.code,
      message: error.message,
      exitCode: error.exitCode,
      ...(error.details === undefined ? {} : { details: error.details }),
    };
  }
  return {
    code: "INTERNAL_ERROR",
    message: "An unexpected internal error occurred.",
    exitCode: 70,
  };
}
