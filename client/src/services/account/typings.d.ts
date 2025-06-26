declare namespace API {
  type CollectionRecord = {
    cloudAccountId?: string;
    alias?: string;
    platform?: string;
    percent?: string;
    startTime?: string;
    endTime?: string;
    errorDetails: ErrorDetail[];
  };

  type ErrorDetail = {
    resourceType: string;
    resourceTypeName: string;
    errorDetailItems: ErrorDetailItem[];
  };

  type ErrorDetailItem = {
    description: string;
    message: string;
    time: string;
  };
}