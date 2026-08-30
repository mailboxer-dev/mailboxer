export type DavService = "calendar" | "contacts";

export type CalendarComponentType = "VEVENT" | "VTODO";

export interface CalendarCollection {
  href: string;
  displayName: string | null;
  description: string | null;
  color: string | null;
  timezone: string | null;
  componentTypes: CalendarComponentType[];
}

export interface AddressBookCollection {
  href: string;
  displayName: string | null;
  description: string | null;
  vcardVersions: string[];
}

export interface CalendarItemFields {
  componentType: CalendarComponentType;
  uid: string | null;
  summary: string | null;
  description: string | null;
  start: string | null;
  end: string | null;
  due: string | null;
  allDay: boolean;
  location: string | null;
  status: string | null;
  priority: number | null;
  percentComplete: number | null;
  completed: string | null;
  rrule: string | null;
  categories: string[];
  url: string | null;
}

export interface CalendarItem extends CalendarItemFields {
  href: string;
  etag: string | null;
  rawIcalendar: string;
  requestedAttachmentPreserved?: boolean;
}

export interface CalendarItemInput {
  componentType: CalendarComponentType;
  uid?: string;
  summary?: string;
  description?: string;
  start?: string;
  end?: string;
  due?: string;
  allDay?: boolean;
  location?: string;
  status?: string;
  priority?: number;
  percentComplete?: number;
  completed?: string;
  rrule?: string;
  categories?: string[];
  url?: string;
  rawIcalendar?: string;
}

export interface ContactName {
  family: string | null;
  given: string | null;
  additional: string | null;
  prefix: string | null;
  suffix: string | null;
}

export interface ContactValue {
  value: string;
  types: string[];
  preferred: boolean;
}

export interface ContactAddress {
  pobox: string | null;
  extended: string | null;
  street: string | null;
  locality: string | null;
  region: string | null;
  postalCode: string | null;
  country: string | null;
  types: string[];
  preferred: boolean;
}

export interface ContactFields {
  uid: string | null;
  formattedName: string | null;
  name: ContactName;
  organization: string[];
  emails: ContactValue[];
  phones: ContactValue[];
  addresses: ContactAddress[];
  birthday: string | null;
  note: string | null;
  urls: string[];
  categories: string[];
}

export interface Contact extends ContactFields {
  href: string;
  etag: string | null;
  rawVcard: string;
}

export interface ContactInput {
  uid?: string;
  formattedName?: string;
  name?: Partial<ContactName>;
  organization?: string[];
  emails?: ContactValue[];
  phones?: ContactValue[];
  addresses?: ContactAddress[];
  birthday?: string;
  note?: string;
  urls?: string[];
  categories?: string[];
  rawVcard?: string;
}

export interface DavItemError {
  href: string;
  status: number;
}

export interface DavPage<T> {
  items: T[];
  errors: DavItemError[];
  lastHref: string | null;
  hasMore: boolean;
}
