export type TaskStatus = 'pending' | 'running' | 'success' | 'failed' | 'cancelled'
export type TaskType = 'single' | 'bulk'

export interface DiscoveryTask {
  id: number
  task_id: string
  task_type: TaskType
  status: TaskStatus
  account: number | null
  account_id: string | null
  account_name: string | null
  regions: string[]
  initiated_by: number
  initiated_by_username: string
  result_summary: {
    vpcs_discovered?: number
    subnets_discovered?: number
    security_groups_discovered?: number
    enis_discovered?: number
  } | null
  error_message: string | null
  total_accounts: number
  completed_accounts: number
  failed_accounts: number
  progress_percentage: number
  duration: number | null
  created_at: string
  started_at: string | null
  completed_at: string | null
  child_tasks?: DiscoveryTask[]
}

export interface TaskSummary {
  total_tasks: number
  pending: number
  running: number
  success: number
  failed: number
  cancelled: number
}

export interface TaskFilters {
  status?: TaskStatus | null
  task_type?: TaskType | null
  ordering?: string
}
