/*
 *    Copyright 2025 blockarchitech
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

import React, { useEffect, useMemo, useState } from 'react';
import {
    Button,
    ButtonContainer,
    ButtonRow,
    Item,
    ItemContainer,
    ItemContainerContent,
    ItemContainerFooter,
    ItemContainerHeader,
    Paragraph,
    Select, SubItem,
    Toggle,
} from '@blockarchitech/shale';
import type {MeResponse} from './types';
import './App.css';

function getAuthFromQuery(): { account: string | null; timeline: string | null } {
    const params = new URLSearchParams(window.location.search);
    return {
        account: params.get('account'),
        timeline: params.get('timeline'),
    };
}

function App() {
    const [{account, timeline}] = useState(getAuthFromQuery());
    const [me, setMe] = useState<MeResponse | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [pinTime, setPinTime] = useState<string | null>(null);
    const [shouldPinNoDueDate, setShouldPinNoDueDate] = useState(false);
    const [shouldPinNoDueTime, setShouldPinNoDueTime] = useState(false);
    const [remindersEnabled, setRemindersEnabled] = useState(false);
    const [reminderTiming, setReminderTiming] = useState<'at' | '30m' | '15m'>('at');
    const [returnToUrl, setReturnToUrl] = useState<string | null>(null); // used to redirect back to pebble if running in emulator


    const authHeader = useMemo(() => {
        if (!account || !timeline) return undefined;
        return 'Bearer ' + btoa(`${account}:${timeline}`);
    }, [account, timeline]);

    useEffect(() => {
        if (window.location.search.includes('return_to=')) {
            const url = new URL(window.location.href);
            const returnTo = url.searchParams.get('return_to');
            if (returnTo) {
                document.cookie = `return_to=${encodeURIComponent(returnTo)}; path=/; max-age=3600`;
                setReturnToUrl(returnTo);
            }
        } else if (document.cookie.includes('return_to=')) {
            const m = document.cookie.match(/(?:^|; )return_to=([^;]+)/);
            if (m) {
                const returnTo = decodeURIComponent(m[1]);
                setReturnToUrl(returnTo);
            }
        } else {
            setReturnToUrl("pebblejs://close");
        }
    }, []);

    useEffect(() => {
        const controller = new AbortController();
        const { signal } = controller;

        async function fetchMe() {
            if (!authHeader) {
                setLoading(false);
                return;
            }
            try {
                const res = await fetch('/api/v1/me', {
                    headers: { Authorization: authHeader },
                    credentials: 'include',
                    signal,
                });
                if (res.status === 401 || res.status === 404) {
                    setMe(null);
                    setLoading(false);
                    return;
                }
                if (!res.ok) throw new Error(`Failed to fetch /me: ${res.status}`);
                const data = (await res.json()) as MeResponse;
                setMe(data);
                setShouldPinNoDueDate(data.preferences.shouldPinWithNoDate);
                setPinTime(data.preferences.shouldPinWithNoTimeAt);
                const rt = (data.preferences.reminderTiming as any) ?? (data.preferences.shouldRemindOnDueTime ? 'at' : '');
                setRemindersEnabled(!!rt);
                setReminderTiming(((rt || 'at') as any));
            } catch (e: any) {
                if (e?.name === 'AbortError') return;
                setError(e.message ?? String(e));
                console.error(e);
            } finally {
                setLoading(false);
            }
        }

        fetchMe();
        return () => {
            controller.abort();
        };
    }, [authHeader]); // fetch when auth header becomes available

    const loginUrl = useMemo(() => {
        const base = new URL('/api/v1/todoist/login', window.location.origin);
        if (account && timeline) {
            base.searchParams.set('token', btoa(`${account}:${timeline}`));
        }
        return base.toString();
    }, [account, timeline]);

    const upgradeUrl = useMemo(() => {
        // Request broader scopes and force consent
        const url = new URL('/api/v1/todoist/login', window.location.origin);
        if (account && timeline) {
            url.searchParams.set('token', btoa(`${account}:${timeline}`));
        }
        url.searchParams.set('scope', 'data:read,data:read_write');
        url.searchParams.set('prompt', 'consent');
        return url.toString();
    }, [account, timeline]);

    const deleteUrl = useMemo(() => {
        const url = new URL('/auth/delete', window.location.origin);
        if (account && timeline) {
            url.searchParams.set('token', btoa(`${account}:${timeline}`));
        }
        return url.toString();
    }, [account, timeline]);

    const getCsrf = () => {
      const m = document.cookie.match(/(?:^|; )ttd_csrf=([^;]+)/);
      return m ? decodeURIComponent(m[1]) : '';
    };

    const onDelete = async () => {
        if (!authHeader) return;
        try {
            window.location.href = deleteUrl; // server page handles UI/redirect
        } catch (e) {
            alert('Error deleting account.');
        }
    };

    const onSave = async () => {
        if (!authHeader) return;
        try {
            if (shouldPinNoDueTime && !pinTime) {
                alert('Please select a time for pins without a due time.');
                return;
            }
            if (shouldPinNoDueDate && !pinTime) {
                alert('Please select a time for pins without a due date.');
            }

            const body = {
                shouldPinWithNoDate: !!shouldPinNoDueDate,
                shouldPinWithNoTime: !!shouldPinNoDueTime,
                shouldPinWithNoTimeAt: shouldPinNoDueDate ? (pinTime ?? '') : '',
                shouldRemindOnDueTime: !!remindersEnabled,
                reminderTiming: remindersEnabled ? (reminderTiming as any) : '',
            };
            const res = await fetch('/api/v1/me', {
                method: 'POST',
                headers: {
                    Authorization: authHeader,
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': getCsrf(),
                },
                credentials: 'include',
                body: JSON.stringify(body),
            });
            if (!res.ok) {
                const text = await res.text();
                throw new Error(`Failed to save preferences: ${res.status} ${text}`);
            }
            // send back to pebble
            if (returnToUrl != null) {
                window.location.href = returnToUrl;
            }
        } catch (e: any) {
            alert(e?.message ?? 'Failed to save preferences.');
        }
    };

    if (loading) {
        return (
            <ItemContainer>
                <ItemContainerContent>
                    <Paragraph>Loading…</Paragraph>
                </ItemContainerContent>
            </ItemContainer>
        );
    }

    if (!account || !timeline) {
        return (
            <ItemContainer>
                <ItemContainerHeader>Missing tokens</ItemContainerHeader>
                <ItemContainerContent>
                    <Paragraph>
                        Open this page from the Pebble app to configure TimeToDo.
                    </Paragraph>
                </ItemContainerContent>
            </ItemContainer>
        );
    }

    if (error) {
        return (
            <ItemContainer>
                <ItemContainerHeader>Error</ItemContainerHeader>
                <ItemContainerContent>
                    <Paragraph>{error}</Paragraph>
                </ItemContainerContent>
                <ItemContainerFooter>
                    <ButtonContainer>
                        <Button onClick={() => window.location.reload()}>
                            Retry
                        </Button>
                    </ButtonContainer>
                </ItemContainerFooter>
            </ItemContainer>
        );
    }

    if (!me) {
        // No account exists yet
        return (
            <>
                <ItemContainer>
                    <ItemContainerHeader>Connect Todoist</ItemContainerHeader>
                    <ItemContainerContent>
                        <Paragraph>
                            It looks like you haven't connected your Todoist account yet.
                        </Paragraph>
                    </ItemContainerContent>
                    <ItemContainerFooter>
                        <ButtonContainer>
                            <Button onClick={() => (window.location.href = loginUrl)}>
                                Login with Todoist
                            </Button>
                        </ButtonContainer>
                    </ItemContainerFooter>
                </ItemContainer>
            </>
        );
    }

    // Logged in
    return (
        <>
            <ItemContainer>
                <ItemContainerHeader>You're connected</ItemContainerHeader>
                <ItemContainerContent>
                    <Item>
                        Todoist User ID
                        <span>#{me.todoistUserID}</span>
                    </Item>
                    <Item>
                        Timezone
                        <span>{me.timezone}</span>
                    </Item>
                    {me.needsUpgrade ? (
                        <Item description={"To enable timeline actions, additional permissions are required."}>
                            Permissions
                            <span>Login Required</span>
                        </Item>
                    ) : (
                        <Item>
                            Permissions
                            <span>All features are enabled.</span>
                        </Item>
                    )}
                </ItemContainerContent>
                <ItemContainerFooter>
                    <ButtonRow>
                        {me.needsUpgrade && (
                            <Button variant={"secondary"} onClick={() => (window.location.href = upgradeUrl)}>
                                Login with Todoist
                            </Button>
                        )}
                        <Button variant="danger" onClick={onDelete} >
                            Disconnect
                        </Button>
                    </ButtonRow>
                </ItemContainerFooter>
            </ItemContainer>

            <ItemContainer>
                <ItemContainerHeader>Options</ItemContainerHeader>
                <ItemContainerContent>
                    {/* should we pin tasks without a due time?  */}
                    <Item
                        description={"When enabled, tasks without a due date will be pinned on the due date with the specified time."}>
                        Pin tasks without a due time
                        <Toggle checked={shouldPinNoDueTime} onChange={e => {
                            const v = e.target.checked;
                            setShouldPinNoDueTime(v);
                            if (v && !pinTime) {
                                setPinTime('09:00');
                            }
                        }}/>
                    </Item>
                    {shouldPinNoDueTime && (
                        <SubItem>
                            When?
                            <Select value={pinTime} onChange={e => setPinTime(e.target.value)}>
                                <option value="00:00">12:00 AM</option>
                                <option value="01:00">1:00 AM</option>
                                <option value="02:00">2:00 AM</option>
                                <option value="03:00">3:00 AM</option>
                                <option value="04:00">4:00 AM</option>
                                <option value="05:00">5:00 AM</option>
                                <option value="06:00">6:00 AM</option>
                                <option value="07:00">7:00 AM</option>
                                <option value="08:00">8:00 AM</option>
                                <option value="09:00">9:00 AM</option>
                                <option value="10:00">10:00 AM</option>
                                <option value="11:00">11:00 AM</option>
                                <option value="12:00">12:00 PM</option>
                                <option value="13:00">1:00 PM</option>
                                <option value="14:00">2:00 PM</option>
                                <option value="15:00">3:00 PM</option>
                                <option value="16:00">4:00 PM</option>
                                <option value="17:00">5:00 PM</option>
                                <option value="18:00">6:00 PM</option>
                                <option value="19:00">7:00 PM</option>
                                <option value="20:00">8:00 PM</option>
                                <option value="21:00">9:00 PM</option>
                                <option value="22:00">10:00 PM</option>
                                <option value="23:00">11:00 PM</option>
                            </Select>
                        </SubItem>
                    )}

                    <Item
                        description={"When enabled, tasks without a due date will be pinned on the created date with the specified time. You must also enable Pin tasks without a due time."}>
                        Pin tasks without a due date
                        <Toggle checked={shouldPinNoDueDate} onChange={e => {
                            const v = e.target.checked;
                            setShouldPinNoDueDate(v);
                            if (v && !shouldPinNoDueTime) { // if this is enabled, and we're not yet pinning without a due time...
                                setShouldPinNoDueTime(v); // ...enable pinning without a due time
                                if (pinTime == "" || pinTime == null) {
                                    setPinTime('09:00'); // ...and set the default pin time, if not already set (user may have previously disabled this option, but we still have their preferences)
                                }
                            }
                        }}/>
                    </Item>

                    <Item description={"Send a watch reminder when a task's due time is reached. Choose when to be reminded."}>
                        Reminders
                        <Toggle checked={remindersEnabled} onChange={e => {
                            const v = e.target.checked;
                            setRemindersEnabled(v);
                            if (v && !reminderTiming) {
                                setReminderTiming('at');
                            }
                        }} />

                    </Item>
                    {remindersEnabled && (
                        <SubItem>
                            When?
                            <Select value={reminderTiming} onChange={e => setReminderTiming(e.target.value as any)}>
                                <option value="at">At due time</option>
                                <option value="30m">30 minutes before</option>
                                <option value="15m">15 minutes before</option>
                            </Select>
                        </SubItem>
                    )}
                </ItemContainerContent>
                <ItemContainerFooter>
                    <ButtonContainer>
                        <Button onClick={onSave}>
                            Save
                        </Button>
                    </ButtonContainer>
                </ItemContainerFooter>
            </ItemContainer>

        </>
    );
}

export default App;
