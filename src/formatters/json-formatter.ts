import { ScanResult } from '../types/index.js';

export class JsonFormatter {
  public static render(result: ScanResult): string {
    return JSON.stringify(result, null, 2);
  }
}
