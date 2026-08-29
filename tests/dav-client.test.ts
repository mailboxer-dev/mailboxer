import { describe, expect, it, vi } from "vitest";
import {
  DavAuthenticationError,
  DavClient,
  DavConflictError,
  DavNotFoundError,
  DavPayloadTooLargeError,
  DavPermissionError,
  type DavFetcher,
} from "../src/dav/client";

const credentials = { email: "owner@icloud.com", password: "app-password" };
const caldavConfig = { caldavUrl: "https://caldav.icloud.com/", carddavUrl: "https://contacts.icloud.com/" };

function response(body: string, status = 207, headers: Record<string, string> = {}): Response {
  return new Response(status === 204 || status === 205 ? null : body, { status, headers });
}

class Transcript {
  readonly calls: Array<{ url: string; method: string; headers: Headers; body: string | undefined }> = [];
  private index = 0;

  constructor(private readonly responses: Response[]) {}

  readonly fetch: DavFetcher = async (input, init) => {
    this.calls.push({
      url: String(input),
      method: init?.method ?? "GET",
      headers: new Headers(init?.headers),
      body: typeof init?.body === "string" ? init.body : undefined,
    });
    const next = this.responses[this.index];
    this.index += 1;
    if (!next) throw new Error("Transcript exhausted");
    return next;
  };
}

function calendarBootstrapResponses(): Response[] {
  return [
    response("", 302, { Location: "https://p1-caldav.icloud.com/.well-known/caldav" }),
    response(`<d:multistatus xmlns:d="DAV:"><d:response><d:href>/principal/</d:href><d:propstat><d:prop><d:current-user-principal><d:href>/principal/</d:href></d:current-user-principal></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`),
    response(`<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:response><d:href>/principal/</d:href><d:propstat><d:prop><c:calendar-home-set><d:href>/calendars/</d:href></c:calendar-home-set></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`),
    response(`<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:response><d:href>/calendars/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/><c:calendar/></d:resourcetype><d:displayname>Personal &amp; Work</d:displayname><c:calendar-description><![CDATA[Owner calendar]]></c:calendar-description><c:calendar-color>#123456</c:calendar-color><c:calendar-timezone>Europe/Paris</c:calendar-timezone><c:supported-calendar-component-set><c:comp name="VEVENT"/><c:comp name="VTODO"/></c:supported-calendar-component-set></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response><d:response><d:href>/calendars/other/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/><c:calendar/></d:resourcetype><d:displayname>Other</d:displayname></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`),
  ];
}

function contactBootstrapResponses(): Response[] {
  return [
    response(`<d:multistatus xmlns:d="DAV:"><d:response><d:href>/principal/</d:href><d:propstat><d:prop><d:current-user-principal><d:href>/principal/</d:href></d:current-user-principal></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`),
    response(`<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><d:response><d:href>/principal/</d:href><d:propstat><d:prop><card:addressbook-home-set><d:href>/addressbooks/</d:href></card:addressbook-home-set></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`),
    response(`<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><d:response><d:href>/addressbooks/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/><card:addressbook/></d:resourcetype><d:displayname>Contacts</d:displayname><card:supported-address-data><card:address-data content-type="text/vcard" version="3.0"/><card:address-data content-type="text/vcard" version="4.0"/></card:supported-address-data></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`),
  ];
}

const eventRaw = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:event-a\r\nDTSTART:20260827T120000Z\r\nSUMMARY:Event A\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
const contactRaw = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:contact-a\r\nFN:Ada Lovelace\r\nN:Lovelace;Ada;;;\r\nEND:VCARD\r\n";

describe("iCloud DAV discovery and live collection access", () => {
  it("calls the default Worker fetch with the correct receiver", async () => {
    const responses = calendarBootstrapResponses();
    const fetcher = vi.fn(function (this: unknown): Promise<Response> {
      expect(this).toBe(globalThis);
      const next = responses.shift();
      if (!next) throw new Error("Transcript exhausted");
      return Promise.resolve(next);
    });
    vi.stubGlobal("fetch", fetcher);
    try {
      await expect(new DavClient(credentials, caldavConfig).listCalendars()).resolves.toHaveLength(2);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("follows only approved HTTPS redirects and discovers CalDAV collections", async () => {
    const transcript = new Transcript(calendarBootstrapResponses());
    const client = new DavClient(credentials, caldavConfig, transcript.fetch);
    await expect(client.listCalendars()).resolves.toEqual([
      {
        href: "https://p1-caldav.icloud.com/calendars/",
        displayName: "Personal & Work",
        description: "Owner calendar",
        color: "#123456",
        timezone: "Europe/Paris",
        componentTypes: ["VEVENT", "VTODO"],
      },
      {
        href: "https://p1-caldav.icloud.com/calendars/other/",
        displayName: "Other",
        description: null,
        color: null,
        timezone: null,
        componentTypes: [],
      },
    ]);
    expect(transcript.calls.map((call) => [call.method, call.url])).toEqual([
      ["PROPFIND", "https://caldav.icloud.com/.well-known/caldav"],
      ["PROPFIND", "https://p1-caldav.icloud.com/.well-known/caldav"],
      ["PROPFIND", "https://p1-caldav.icloud.com/principal/"],
      ["PROPFIND", "https://p1-caldav.icloud.com/calendars/"],
    ]);
    expect(transcript.calls.every((call) => call.headers.get("Authorization") === "Basic b3duZXJAaWNsb3VkLmNvbTphcHAtcGFzc3dvcmQ=")).toBe(true);
    expect(transcript.calls[0]?.headers.get("Cache-Control")).toBe("no-store");
  });

  it("rejects an unapproved redirect and never sends credentials to it", async () => {
    const transcript = new Transcript([response("", 302, { Location: "https://evil.example/steal" })]);
    const client = new DavClient(credentials, caldavConfig, transcript.fetch);
    await expect(client.listCalendars()).rejects.toThrow("unsafe");
    expect(transcript.calls).toHaveLength(1);
    expect(transcript.calls[0]?.headers.get("Authorization")).toBe("Basic b3duZXJAaWNsb3VkLmNvbTphcHAtcGFzc3dvcmQ=");
  });

  it("confines custom DAV discovery to its configured host and uses its account username", async () => {
    const transcript = new Transcript([response("", 302, { Location: "https://other.example/steal" })]);
    const client = new DavClient(
      { email: "owner@example.com", password: "account-password" },
      { caldavUrl: "https://dav.example.com/", username: "dav-user" },
      transcript.fetch,
    );
    await expect(client.listCalendars()).rejects.toThrow("unsafe");
    expect(transcript.calls).toHaveLength(1);
    expect(transcript.calls[0]?.url).toBe("https://dav.example.com/.well-known/caldav");
    expect(transcript.calls[0]?.headers.get("Authorization")).toBe("Basic ZGF2LXVzZXI6YWNjb3VudC1wYXNzd29yZA==");
  });

  it("accepts same-host resource hrefs for a custom DAV provider", async () => {
    const transcript = new Transcript([
      response(`<d:multistatus xmlns:d="DAV:"><d:response><d:href>/principal/</d:href><d:propstat><d:prop><d:current-user-principal><d:href>/principal/</d:href></d:current-user-principal></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`),
      response(`<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:response><d:href>/principal/</d:href><d:propstat><d:prop><c:calendar-home-set><d:href>/calendars/</d:href></c:calendar-home-set></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`),
      response(`<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:response><d:href>/calendars/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/><c:calendar/></d:resourcetype><d:displayname>Personal</d:displayname></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`),
    ]);
    const client = new DavClient(
      { email: "owner@example.com", password: "account-password" },
      { caldavUrl: "https://dav.example.com/", username: "dav-user" },
      transcript.fetch,
    );
    await expect(client.listCalendars()).resolves.toMatchObject([{ href: "https://dav.example.com/calendars/personal/" }]);
  });

  it("discovers CardDAV address books and supported vCard versions", async () => {
    const transcript = new Transcript(contactBootstrapResponses());
    const client = new DavClient(credentials, caldavConfig, transcript.fetch);
    await expect(client.listAddressBooks()).resolves.toEqual([{
      href: "https://contacts.icloud.com/addressbooks/",
      displayName: "Contacts",
      description: null,
      vcardVersions: ["3.0", "4.0"],
    }]);
    expect(transcript.calls.map((call) => call.method)).toEqual(["PROPFIND", "PROPFIND", "PROPFIND"]);
  });
});

describe("iCloud DAV reports and conditional writes", () => {
  it("uses calendar-query and calendar-multiget with sorted, bounded UID-like href pagination", async () => {
    const queryResponse = `<d:multistatus xmlns:d="DAV:"><d:response><d:href>/calendars/a/b.ics</d:href><d:propstat><d:prop><d:getetag>"b"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response><d:response><d:href>/calendars/a/a.ics</d:href><d:propstat><d:prop><d:getetag>"a"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`;
    const multigetResponse = `<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:response><d:href>/calendars/a/a.ics</d:href><d:propstat><d:prop><d:getetag>"a"</d:getetag><c:calendar-data><![CDATA[${eventRaw}]]></c:calendar-data></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`;
    const transcript = new Transcript([response(queryResponse), response(queryResponse), response(queryResponse), response(multigetResponse)]);
    const client = new DavClient(credentials, caldavConfig, transcript.fetch);
    const page = await client.listCalendarItems({ calendarHref: "https://caldav.icloud.com/calendars/a/", componentType: "VEVENT", text: "A&<", start: "2026-08-27", end: "2026-08-28" }, undefined, 1);
    expect(page.items[0]).toMatchObject({ href: "https://caldav.icloud.com/calendars/a/a.ics", uid: "event-a", etag: '"a"' });
    expect(page.hasMore).toBe(true);
    expect(page.lastHref).toBe("https://caldav.icloud.com/calendars/a/a.ics");
    expect(transcript.calls[0]?.body).toContain("A&amp;&lt;");
    expect(transcript.calls[0]?.body).toContain("calendar-query");
    expect(transcript.calls.at(-1)?.body).toContain("calendar-multiget");
    expect(transcript.calls.at(-1)?.body).toContain("a.ics");
  });

  it("serializes absolute CalDAV shard hrefs as escaped relative multiget hrefs", async () => {
    const canonicalHref = "https://p122-caldav.icloud.com/calendars/a/event-a.ics?rev=1&part=2";
    const responseHref = "https://p122-caldav.icloud.com/calendars/a/event-a.ics?rev=1&amp;part=2";
    const queryResponse = `<d:multistatus xmlns:d="DAV:"><d:response><d:href>${responseHref}</d:href><d:propstat><d:prop><d:getetag>"event-a"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`;
    const multigetResponse = `<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:response><d:href>${responseHref}</d:href><d:propstat><d:prop><d:getetag>"event-a"</d:getetag><c:calendar-data><![CDATA[${eventRaw}]]></c:calendar-data></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`;
    const transcript = new Transcript([response(queryResponse), response(multigetResponse)]);
    const client = new DavClient(credentials, caldavConfig, transcript.fetch);

    const page = await client.listCalendarItems({ calendarHref: "https://p122-caldav.icloud.com/calendars/a/", componentType: "VEVENT" }, undefined, 50);
    const multigetBody = transcript.calls.at(-1)?.body;

    expect(page.items[0]).toMatchObject({ href: canonicalHref, uid: "event-a", etag: '"event-a"' });
    expect(multigetBody).toContain('<d:href>/calendars/a/event-a.ics?rev=1&amp;part=2</d:href>');
    expect(multigetBody).not.toMatch(/<d:href>https:\/\//u);
  });

  it("serializes absolute CardDAV shard hrefs as escaped relative multiget hrefs", async () => {
    const canonicalHref = "https://p122-contacts.icloud.com/addressbooks/a/contact-a.vcf?rev=1&part=2";
    const responseHref = "https://p122-contacts.icloud.com/addressbooks/a/contact-a.vcf?rev=1&amp;part=2";
    const queryResponse = `<d:multistatus xmlns:d="DAV:"><d:response><d:href>${responseHref}</d:href><d:propstat><d:prop><d:getetag>"contact-a"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`;
    const multigetResponse = `<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><d:response><d:href>${responseHref}</d:href><d:propstat><d:prop><d:getetag>"contact-a"</d:getetag><card:address-data><![CDATA[${contactRaw}]]></card:address-data></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`;
    const transcript = new Transcript([response(queryResponse), response(multigetResponse)]);
    const client = new DavClient(credentials, caldavConfig, transcript.fetch);

    const page = await client.listContacts({ addressBookHref: "https://p122-contacts.icloud.com/addressbooks/a/" }, undefined, 50);
    const multigetBody = transcript.calls.at(-1)?.body;

    expect(page.items[0]).toMatchObject({ href: canonicalHref, uid: "contact-a", etag: '"contact-a"' });
    expect(multigetBody).toContain('<d:href>/addressbooks/a/contact-a.vcf?rev=1&amp;part=2</d:href>');
    expect(multigetBody).not.toMatch(/<d:href>https:\/\//u);
  });

  it("uses an object-level filter for an unfiltered any-component query", async () => {
    const queryResponse = `<d:multistatus xmlns:d="DAV:"><d:response><d:href>/calendars/a/event.ics</d:href><d:propstat><d:prop><d:getetag>"event"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response><d:response><d:href>/calendars/a/todo.ics</d:href><d:propstat><d:prop><d:getetag>"todo"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`;
    const multigetResponse = `<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:response><d:href>/calendars/a/event.ics</d:href><d:propstat><d:prop><d:getetag>"event"</d:getetag><c:calendar-data><![CDATA[${eventRaw}]]></c:calendar-data></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response><d:response><d:href>/calendars/a/todo.ics</d:href><d:propstat><d:prop><d:getetag>"todo"</d:getetag><c:calendar-data><![CDATA[${"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VTODO\r\nUID:todo-a\r\nSUMMARY:Todo A\r\nEND:VTODO\r\nEND:VCALENDAR\r\n"}]]></c:calendar-data></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`;
    const transcript = new Transcript([response(queryResponse), response(multigetResponse)]);
    const client = new DavClient(credentials, caldavConfig, transcript.fetch);
    const page = await client.listCalendarItems({ calendarHref: "https://caldav.icloud.com/calendars/a/", componentType: "any" }, undefined, 50);
    expect(page.items.map((item) => item.componentType)).toEqual(["VEVENT", "VTODO"]);
    expect(transcript.calls[0]?.body).toContain('<c:comp-filter name="VCALENDAR"></c:comp-filter>');
    expect(transcript.calls[0]?.body).not.toContain('<c:comp-filter name="VEVENT">');
  });

  it("returns per-resource multistatus errors without hiding successful contacts", async () => {
    const queryResponse = `<d:multistatus xmlns:d="DAV:"><d:response><d:href>/addressbooks/a/good.vcf</d:href><d:propstat><d:prop><d:getetag>"good"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response><d:response><d:href>/addressbooks/a/missing.vcf</d:href><d:propstat><d:prop/><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat></d:response></d:multistatus>`;
    const multigetResponse = `<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><d:response><d:href>/addressbooks/a/good.vcf</d:href><d:propstat><d:prop><d:getetag>"good"</d:getetag><card:address-data><![CDATA[${contactRaw}]]></card:address-data></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response><d:response><d:href>/addressbooks/a/missing.vcf</d:href><d:status>HTTP/1.1 404 Not Found</d:status></d:response></d:multistatus>`;
    const transcript = new Transcript([
      response(queryResponse),
      response(queryResponse),
      response(queryResponse),
      response(queryResponse),
      response(queryResponse),
      response(multigetResponse),
    ]);
    const client = new DavClient(credentials, caldavConfig, transcript.fetch);
    const page = await client.listContacts({ addressBookHref: "https://contacts.icloud.com/addressbooks/a/", query: "Ada" }, undefined, 50);
    expect(page.items).toHaveLength(1);
    expect(page.items[0]?.formattedName).toBe("Ada Lovelace");
    expect(page.errors).toEqual([{ href: "https://contacts.icloud.com/addressbooks/a/missing.vcf", status: 404 }]);
    expect(transcript.calls[0]?.body).toContain("addressbook-query");
    expect(transcript.calls.at(-1)?.body).toContain("addressbook-multiget");
  });

  it("requires If-Match for updates/deletes and uses If-None-Match for creates", async () => {
    const createTranscript = new Transcript([response("", 204, { ETag: '"created"' })]);
    const client = new DavClient(credentials, caldavConfig, createTranscript.fetch);
    const created = await client.createCalendarItem("https://caldav.icloud.com/calendars/a/", {
      componentType: "VEVENT",
      uid: "created-event",
      summary: "Created",
      start: "2026-08-27T12:00:00Z",
    });
    expect(created.etag).toBe('"created"');
    expect(createTranscript.calls[0]?.method).toBe("PUT");
    expect(createTranscript.calls[0]?.headers.get("If-None-Match")).toBe("*");

    const updateTranscript = new Transcript([response("", 204, { ETag: '"new"' })]);
    const updater = new DavClient(credentials, caldavConfig, updateTranscript.fetch);
    const updated = await updater.updateCalendarItem("https://caldav.icloud.com/calendars/a/event.ics", '"old"', {
      componentType: "VEVENT",
      rawIcalendar: eventRaw,
    });
    expect(updated.etag).toBe('"new"');
    expect(updateTranscript.calls[0]?.headers.get("If-Match")).toBe('"old"');

    const deleteTranscript = new Transcript([response("", 204)]);
    const deleter = new DavClient(credentials, caldavConfig, deleteTranscript.fetch);
    await expect(deleter.deleteContact("https://contacts.icloud.com/addressbooks/a/contact.vcf", '"etag"')).resolves.toBeUndefined();
    expect(deleteTranscript.calls[0]?.method).toBe("DELETE");
    expect(deleteTranscript.calls[0]?.headers.get("If-Match")).toBe('"etag"');
  });
});

describe("DAV status and response bounds", () => {
  it.each([
    [401, DavAuthenticationError],
    [403, DavPermissionError],
    [404, DavNotFoundError],
    [409, DavConflictError],
    [412, DavConflictError],
  ])("maps HTTP %s to a safe protocol error", async (status, errorType) => {
    const transcript = new Transcript([response("", status)]);
    const client = new DavClient(credentials, caldavConfig, transcript.fetch);
    await expect(client.getCalendarItem("https://caldav.icloud.com/event.ics")).rejects.toBeInstanceOf(errorType);
  });

  it("maps server failures and rejects over-large resource bodies", async () => {
    const serverFailure = new Transcript([response("", 503)]);
    await expect(new DavClient(credentials, caldavConfig, serverFailure.fetch).getContact("https://contacts.icloud.com/contact.vcf"))
      .rejects.toThrow("temporarily unavailable");

    const tooLarge = new Transcript([response("small", 200, { "Content-Length": String(512 * 1024 + 1) })]);
    await expect(new DavClient(credentials, caldavConfig, tooLarge.fetch).getContact("https://contacts.icloud.com/contact.vcf"))
      .rejects.toBeInstanceOf(DavPayloadTooLargeError);
  });

  it("does not forward credentials after an unsafe principal href", async () => {
    const transcript = new Transcript([response(`<d:multistatus xmlns:d="DAV:"><d:response><d:href>/</d:href><d:propstat><d:prop><d:current-user-principal><d:href>https://evil.example/principal</d:href></d:current-user-principal></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`) ]);
    const client = new DavClient(credentials, caldavConfig, transcript.fetch);
    await expect(client.listCalendars()).rejects.toThrow("unsafe");
    expect(transcript.calls).toHaveLength(1);
  });

  it("can be instrumented with an injected fetcher without persistent client state", async () => {
    const fetcher = vi.fn<DavFetcher>(async () => response("", 404));
    const client = new DavClient(credentials, caldavConfig, fetcher);
    await expect(client.getCalendarItem("https://caldav.icloud.com/event.ics")).rejects.toBeInstanceOf(DavNotFoundError);
    expect(fetcher).toHaveBeenCalledOnce();
  });
});
