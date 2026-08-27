import { describe, expect, it } from "vitest";
import { parseCalendarResource, serializeCalendarItem, IcalendarParseError } from "../src/dav/ical";
import { parseContactResource, serializeContact, VcardParseError } from "../src/dav/vcard";
import type { CalendarItemInput, ContactInput } from "../src/dav/types";

const MAX_RESOURCE_BYTES = 512 * 1024;

describe("bounded iCalendar parsing and serialization", () => {
  it("handles folding, escaped text, Unicode, dates, recurrence, and VTODO fields", () => {
    const eventRaw = [
      "BEGIN:VCALENDAR",
      "VERSION:2.0",
      "BEGIN:VEVENT",
      "UID:event-1",
      "DTSTART;VALUE=DATE:20260827",
      "DTEND;VALUE=DATE:20260828",
      "SUMMARY:Quarterly\\, review",
      "DESCRIPTION:Line one\\nLine two",
      "RRULE:FREQ=DAILY;COUNT=2",
      "CATEGORIES:work,planning",
      "END:VEVENT",
      "END:VCALENDAR",
      "",
    ].join("\r\n");
    const event = parseCalendarResource(eventRaw, "https://caldav.icloud.com/calendars/a/event.ics", '"event-1"', MAX_RESOURCE_BYTES);
    expect(event).toMatchObject({
      componentType: "VEVENT",
      uid: "event-1",
      summary: "Quarterly, review",
      description: "Line one\nLine two",
      start: "2026-08-27",
      end: "2026-08-28",
      allDay: true,
      rrule: "FREQ=DAILY;COUNT=2",
      categories: ["work", "planning"],
    });
    expect(event.rawIcalendar).toBe(eventRaw);

    const todoRaw = [
      "BEGIN:VCALENDAR",
      "VERSION:2.0",
      "BEGIN:VTODO",
      "UID:todo-1",
      "SUMMARY:Remember Unicode café",
      "DUE:20260828T120000Z",
      "STATUS:NEEDS-ACTION",
      "PERCENT-COMPLETE:25",
      "END:VTODO",
      "END:VCALENDAR",
      "",
    ].join("\r\n");
    expect(parseCalendarResource(todoRaw, "https://caldav.icloud.com/calendars/a/todo.ics", null, MAX_RESOURCE_BYTES)).toMatchObject({
      componentType: "VTODO",
      summary: "Remember Unicode café",
      due: "2026-08-28T12:00:00Z",
      percentComplete: 25,
    });
  });

  it("serializes structured events and preserves escaped line breaks without injection", () => {
    const input: CalendarItemInput = {
      componentType: "VEVENT",
      uid: "safe-event",
      summary: "A\nB",
      description: "Line one\r\nLine two",
      start: "2026-08-27T12:30:00Z",
      end: "2026-08-27T13:30:00Z",
      location: "Room; 2",
    };
    const raw = serializeCalendarItem(input, new Date("2026-08-27T00:00:00Z"));
    expect(raw).toContain("SUMMARY:A\\nB\r\n");
    expect(raw).not.toContain("SUMMARY:A\r\nB");
    expect(parseCalendarResource(raw, "https://caldav.icloud.com/event.ics", null, MAX_RESOURCE_BYTES)).toMatchObject({
      uid: "safe-event",
      summary: "A\nB",
      description: "Line one\nLine two",
      location: "Room; 2",
    });
    expect(() => serializeCalendarItem({ ...input, url: "https://example.test/a\r\nX-Injected: yes" })).toThrow(IcalendarParseError);
  });

  it("folds long UTF-8 lines without changing their value", () => {
    const summary = "é".repeat(120);
    const raw = serializeCalendarItem({ componentType: "VEVENT", uid: "folded", summary });
    expect(raw).toContain("\r\n ");
    expect(parseCalendarResource(raw, "https://caldav.icloud.com/event.ics", null, MAX_RESOURCE_BYTES).summary).toBe(summary);
  });

  it("rejects malformed boundaries and control characters", () => {
    expect(() => parseCalendarResource("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n", "https://caldav.icloud.com/a", null, MAX_RESOURCE_BYTES)).toThrow(IcalendarParseError);
    expect(() => parseCalendarResource("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nSUMMARY:bad\u0001\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n", "https://caldav.icloud.com/a", null, MAX_RESOURCE_BYTES)).toThrow(IcalendarParseError);
  });
});

describe("bounded vCard parsing and serialization", () => {
  it("handles vCard 3/4 properties, folding, escaped delimiters, and parameters", () => {
    const raw = [
      "BEGIN:VCARD",
      "VERSION:4.0",
      "UID:contact-1",
      "FN:Renée Example",
      "N:Example;Renée;Marie;Dr.;PhD",
      "ORG:Example\\; Labs;Research",
      "EMAIL;TYPE=internet,home;PREF=1:renee@example.com",
      "TEL;TYPE=cell:+33123456789",
      "ADR;TYPE=home:;;1 Rue de l\\;Église;Paris;;75001;France",
      "BDAY:1980-01-02",
      "NOTE:Line one\\nLine two",
      "CATEGORIES:friend,work",
      "URL:https://example.test/contact",
      "END:VCARD",
      "",
    ].join("\r\n");
    const contact = parseContactResource(raw, "https://contacts.icloud.com/addressbooks/a/contact.vcf", '"contact-1"', MAX_RESOURCE_BYTES);
    expect(contact).toMatchObject({
      uid: "contact-1",
      formattedName: "Renée Example",
      name: { family: "Example", given: "Renée", additional: "Marie", prefix: "Dr.", suffix: "PhD" },
      organization: ["Example; Labs", "Research"],
      emails: [{ value: "renee@example.com", types: ["INTERNET", "HOME"], preferred: true }],
      phones: [{ value: "+33123456789", types: ["CELL"], preferred: false }],
      addresses: [{ street: "1 Rue de l;Église", locality: "Paris", postalCode: "75001", country: "France" }],
      birthday: "1980-01-02",
      note: "Line one\nLine two",
      categories: ["friend", "work"],
    });
    expect(contact.rawVcard).toBe(raw);
  });

  it("serializes structured contacts and rejects header injection", () => {
    const input: ContactInput = {
      uid: "contact-2",
      formattedName: "Ada Lovelace",
      name: { family: "Lovelace", given: "Ada" },
      emails: [{ value: "ada@example.com", types: ["work"], preferred: true }],
      note: "Line one\nLine two",
      urls: ["https://example.test/ada"],
    };
    const raw = serializeContact(input);
    expect(raw).toContain("VERSION:3.0\r\n");
    expect(raw).not.toContain("FN:Ada Lovelace\r\nInjected");
    expect(parseContactResource(raw, "https://contacts.icloud.com/contact.vcf", null, MAX_RESOURCE_BYTES)).toMatchObject({
      uid: "contact-2",
      formattedName: "Ada Lovelace",
      emails: [{ value: "ada@example.com", preferred: true }],
      note: "Line one\nLine two",
    });
    expect(() => serializeContact({ ...input, urls: ["https://example.test\r\nX-Injected: yes"] })).toThrow(VcardParseError);
  });

  it("folds long vCard values without changing their value", () => {
    const formattedName = "É".repeat(120);
    const raw = serializeContact({ uid: "folded", formattedName });
    expect(raw).toContain("\r\n ");
    expect(parseContactResource(raw, "https://contacts.icloud.com/contact.vcf", null, MAX_RESOURCE_BYTES).formattedName).toBe(formattedName);
  });

  it("rejects malformed vCards and oversized resources", () => {
    expect(() => parseContactResource("BEGIN:VCARD\r\nFN:missing end\r\n", "https://contacts.icloud.com/a", null, MAX_RESOURCE_BYTES)).toThrow(VcardParseError);
    expect(() => parseContactResource("BEGIN:VCARD\r\nVERSION:3.0\r\nFN:bad\u0001\r\nEND:VCARD\r\n", "https://contacts.icloud.com/a", null, MAX_RESOURCE_BYTES)).toThrow(VcardParseError);
    expect(() => parseContactResource("x".repeat(MAX_RESOURCE_BYTES + 1), "https://contacts.icloud.com/a", null, MAX_RESOURCE_BYTES)).toThrow(VcardParseError);
  });
});
