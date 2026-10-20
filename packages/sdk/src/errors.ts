/**
 * @sug/sdk - Error Definitions
 * Standard RFC 7807 Problem Details Error Representation for Client SDK
 */

export interface ProblemDetailsData {
  type?: string | undefined;
  title?: string | undefined;
  status?: number | undefined;
  detail?: string | undefined;
  instance?: string | undefined;
  requestId?: string | undefined;
  details?: Record<string, unknown> | undefined;
}

export class SugApiError extends Error {
  public readonly status: number;
  public readonly type: string;
  public readonly title: string;
  public readonly detail: string;
  public readonly instance?: string | undefined;
  public readonly requestId?: string | undefined;
  public readonly details?: Record<string, unknown> | undefined;

  constructor(status: number, problem: ProblemDetailsData) {
    const detailMessage = problem.detail || problem.title || `HTTP ${status} API error`;
    super(detailMessage);

    this.name = 'SugApiError';
    this.status = status;
    this.type = problem.type || `urn:sug:error:http-${status}`;
    this.title = problem.title || 'API Error';
    this.detail = detailMessage;
    this.instance = problem.instance;
    this.requestId = problem.requestId;
    this.details = problem.details;

    // Ensure prototype chain is maintained
    Object.setPrototypeOf(this, new.target.prototype);
  }

  /**
   * Safe string representation ensuring no credential tokens or sensitive headers leak.
   */
  public override toString(): string {
    return `${this.name} [${this.status}] ${this.title}: ${this.detail} (requestId: ${this.requestId ?? 'none'})`;
  }
}
