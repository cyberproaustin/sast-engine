// The collaborator both handlers talk to. Its bodies are deliberately empty: what this
// corpus is about is which of them a handler CALLS, not what any of them does.
export const featureService = {
  async validateFeatureBelongsToProject(_ctx: { featureName: string; projectId: string }) {},
  async validateWidgetBelongsToProject(_ctx: { widgetId: string; projectId: string }) {},
  async readVariants(_featureName: string, _environment: string): Promise<string[]> {
    return [];
  },
  async saveVariants(
    _featureName: string,
    _projectId: string,
    _environment: string,
    _body: unknown,
    _user: unknown,
  ): Promise<string[]> {
    return [];
  },
  async readWidget(_widgetId: string): Promise<string> {
    return "";
  },
  async saveWidget(_widgetId: string, _projectId: string, _body: unknown) {},
  async hasPermission(_user: unknown, _projectId: string): Promise<boolean> {
    return true;
  },
  async readSegments(_projectId: string): Promise<string[]> {
    return [];
  },
  async saveSegment(_projectId: string, _body: unknown) {},
  async readReport(_reportId: string, _range: string): Promise<string> {
    return "";
  },
  async saveReport(_reportId: string, _body: unknown) {},
  async validateDateRange(_range: string) {},
};
