import {ActionTestActivitySummary} from '../dev/@types/ActionTestActivitySummary'
import {Attachment} from './attachment'

export interface Activity {
  title: string
  activityType: string
  uuid: string
  start?: string
  finish?: string
  attachments: Attachment[]
  subactivities: ActionTestActivitySummary[]
  failureSummaryIDs: string[]
  expectedFailureIDs: string[]
  indent: number
}
