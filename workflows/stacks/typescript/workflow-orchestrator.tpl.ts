export type WorkflowContext = {
  userId: string;
  requestId: string;
};

export async function runWorkflow(_ctx: WorkflowContext): Promise<void> {
  throw new Error('TODO: orchestrate [[WORKFLOW_ID]]');
}
