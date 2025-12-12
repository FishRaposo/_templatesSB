class WorkflowContext {
  final String userId;
  final String requestId;

  const WorkflowContext({required this.userId, required this.requestId});
}

class WorkflowFlowController {
  // Generated stub for workflow: [[WORKFLOW_ID]]
  const WorkflowFlowController();

  Future<void> run({
    required WorkflowContext ctx,
  }) async {
    throw UnimplementedError('TODO: orchestrate [[WORKFLOW_ID]]');
  }
}
