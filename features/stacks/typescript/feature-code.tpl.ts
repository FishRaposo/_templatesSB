export type FeatureContext = {
  userId?: string;
  requestId: string;
};

export class FeatureImplementation {
  // Generated stub for feature: [[FEATURE_ID]]
  execute(_ctx: FeatureContext, _inputs: Record<string, unknown>): Record<string, unknown> {
    throw new Error('TODO: implement [[FEATURE_ID]]');
  }
}
