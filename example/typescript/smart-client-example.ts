import { Client } from '../../src/generators/typescript/static/index';
import type { Patient, Bundle } from './aidbox/types/hl7-fhir-r4-core';

// Simple in-memory token storage
const createMemoryStorage = () => {
  let token: string | undefined;
  return {
    get: () => token || null,
    set: (newToken: string | undefined) => {
      token = newToken;
    }
  };
};

// Example 1: Create client with SMART authentication
async function exampleSmartAuth() {
  // Create a client with SMART authentication
  const client = new Client('https://api.logicahealth.org/PACIO/open', {
    auth: {
      method: 'smart',
      clientId: 'my-client-id',
      redirectUri: 'https://my-app.example.com/callback',
      scope: 'patient/*.read launch/patient',
      storage: createMemoryStorage()
    }
  });

  // Check if we're on the callback page
  if (window.location.pathname === '/callback') {
    try {
      // Handle the OAuth callback
      await client.auth.handleCallback(window.location.href);
      console.log('Authentication successful');
      
      // Redirect back to main page
      window.location.href = '/';
      return;
    } catch (error) {
      console.error('Authentication failed:', error);
    }
  }

  try {
    // Try to get patient data - this will trigger auth if needed
    const patient = await client.resource.get<Patient>('Patient', '123');
    console.log('Patient data:', patient);
  } catch (error) {
    console.error('Error:', error);
    
    // Start authorization process
    await client.auth.authorize();
  }
}

// Example 2: Search for resources using SMART authentication
async function exampleSmartSearch() {
  const client = new Client('https://api.logicahealth.org/PACIO/open', {
    auth: {
      method: 'smart',
      clientId: 'my-client-id',
      redirectUri: 'https://my-app.example.com/callback',
      scope: 'patient/*.read launch/patient',
      storage: createMemoryStorage()
    }
  });

  try {
    // Search for observations
    const searchResult = await client.resource.search<'Observation'>('Observation')
      .where('patient', 'Patient/123')
      .where('code', 'http://loinc.org|8867-4')
      .where('_count', '10');
    
    console.log(`Found ${searchResult.total} observations`);
    
    searchResult.entry?.forEach(entry => {
      const observation = entry.resource;
      console.log(`Observation: ${observation.id}, Value: ${observation.valueQuantity?.value} ${observation.valueQuantity?.unit}`);
    });
  } catch (error) {
    console.error('Error:', error);
    
    // Start authorization process if needed
    await client.auth.authorize();
  }
}

// Example 3: Using with EHR launch context
async function exampleEHRLaunch() {
  // Get launch parameters from URL
  const urlParams = new URLSearchParams(window.location.search);
  const launch = urlParams.get('launch');
  const iss = urlParams.get('iss');
  
  if (!launch || !iss) {
    console.error('Missing launch parameters');
    return;
  }
  
  const client = new Client(iss, {
    auth: {
      method: 'smart',
      clientId: 'my-client-id',
      redirectUri: 'https://my-app.example.com/callback',
      scope: 'launch patient/*.read',
      launch,
      storage: createMemoryStorage()
    }
  });
  
  // Start the authorization flow
  await client.auth.authorize();
} 